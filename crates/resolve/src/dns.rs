use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use hickory_resolver::config::{CLOUDFLARE, NameServerConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::DnsHandle;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::{
    DnsRequest, DnsRequestOptions, Edns, Message, Query, ResponseCode,
};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use weft_core::{Address, PublicKey, address::Kind};

use crate::error::{Error, Result};

pub const LABEL: &str = "_weft";
pub const PREFIX: &[u8] = b"weft=";
pub const TIMEOUT: Duration = Duration::from_secs(5);
pub const MIN_TTL: Duration = Duration::from_secs(60);
pub const MAX_TTL: Duration = Duration::from_secs(3600);
pub const MAX_ENTRIES: usize = 1024;
const PAYLOAD: u16 = 1232;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub author: PublicKey,
    pub authentic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negative {
    NoRecord,
    Binding(&'static str),
}

impl Negative {
    fn error(self, host: &str) -> Error {
        match self {
            Self::NoRecord => Error::Dns(format!("no {LABEL} record at {host}")),
            Self::Binding(why) => Error::Binding(why),
        }
    }
}

pub type Outcome = core::result::Result<Binding, Negative>;

pub fn parse<'a>(records: impl IntoIterator<Item = &'a [u8]>, authentic: bool) -> Outcome {
    let mut found = None;
    for record in records {
        let Some(value) = record.strip_prefix(PREFIX) else { continue };
        if found.is_some() {
            return Err(Negative::Binding("more than one weft record"));
        }
        found = Some(value);
    }
    let value = found.ok_or(Negative::Binding("no weft record"))?;
    let text = core::str::from_utf8(value).map_err(|_| Negative::Binding("not utf-8"))?;
    let address: Address = text.parse().map_err(|_| Negative::Binding("not an address"))?;
    if address.kind() != Kind::Key {
        return Err(Negative::Binding("not a key address"));
    }
    let author =
        PublicKey::from_bytes(address.bytes()).map_err(|_| Negative::Binding("not a key"))?;
    Ok(Binding { author, authentic })
}

#[derive(Debug, Default)]
struct Cache {
    entries: HashMap<String, (Outcome, Instant)>,
}

impl Cache {
    fn get(&mut self, host: &str, now: Instant) -> Option<Outcome> {
        match self.entries.get(host) {
            Some((outcome, until)) if *until > now => Some(outcome.clone()),
            Some(_) => {
                self.entries.remove(host);
                None
            }
            None => None,
        }
    }

    fn put(&mut self, host: &str, outcome: Outcome, ttl: u32, now: Instant) {
        self.entries.retain(|_, (_, until)| *until > now);
        if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(host) {
            let soonest = self
                .entries
                .iter()
                .min_by_key(|(_, (_, until))| *until)
                .map(|(host, _)| host.clone());
            if let Some(host) = soonest {
                self.entries.remove(&host);
            }
        }
        let ttl = Duration::from_secs(u64::from(ttl)).clamp(MIN_TTL, MAX_TTL);
        self.entries.insert(host.to_owned(), (outcome, now + ttl));
    }
}

#[derive(Clone)]
pub struct Dns {
    pool: NameServerPool<TokioRuntimeProvider>,
    cache: Arc<Mutex<Cache>>,
}

impl core::fmt::Debug for Dns {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Dns")
    }
}

impl Dns {
    pub fn new(server: Option<&str>) -> Result<Self> {
        let servers: Vec<NameServerConfig> = match server {
            None => CLOUDFLARE.https().collect(),
            Some(spec) => {
                let (ip, name) = spec
                    .split_once(',')
                    .ok_or_else(|| Error::Dns("WEFT_DOH wants ip,name".into()))?;
                let ip: IpAddr = ip.trim().parse().map_err(|_| Error::Dns("WEFT_DOH ip".into()))?;
                vec![NameServerConfig::https(ip, Arc::from(name.trim()), None)]
            }
        };
        Self::over(servers)
    }

    #[cfg(test)]
    fn udp(addr: std::net::SocketAddr) -> Result<Self> {
        let mut connection = hickory_resolver::config::ConnectionConfig::udp();
        connection.port = addr.port();
        Self::over(vec![NameServerConfig::new(addr.ip(), true, vec![connection])])
    }

    fn over(servers: Vec<NameServerConfig>) -> Result<Self> {
        let mut options = ResolverOpts::default();
        options.timeout = TIMEOUT;
        options.attempts = 1;
        let tls = TlsConfig::new().map_err(|e| Error::Dns(e.to_string()))?;
        let cx = Arc::new(PoolContext::new(options, tls));
        Ok(Self {
            pool: NameServerPool::from_config(servers, cx, TokioRuntimeProvider::default()),
            cache: Arc::default(),
        })
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub async fn lookup(&self, host: &str) -> Result<Binding> {
        if let Some(outcome) = self.cache().get(host, Instant::now()) {
            return outcome.map_err(|n| n.error(host));
        }
        let name =
            Name::from_ascii(format!("{LABEL}.{host}.")).map_err(|e| Error::Dns(e.to_string()))?;
        let mut message = Message::query();
        message.add_query(Query::query(name, RecordType::TXT));
        message.metadata.recursion_desired = true;
        message.metadata.authentic_data = true;
        let mut edns = Edns::new();
        edns.set_max_payload(PAYLOAD).set_dnssec_ok(true);
        message.set_edns(edns);
        let mut options = DnsRequestOptions::default();
        options.edns_set_dnssec_ok = true;
        let mut stream = self.pool.send(DnsRequest::new(message, options));
        let answer = stream.next().await.ok_or_else(|| Error::Dns("no response".into()))?;
        let (outcome, ttl) = match answer {
            Ok(response) => {
                let txt: Vec<_> = response
                    .answers
                    .iter()
                    .filter(|r| r.record_type() == RecordType::TXT)
                    .collect();
                match response.metadata.response_code {
                    ResponseCode::NoError => {
                        let strings: Vec<Vec<u8>> = txt
                            .iter()
                            .filter_map(|r| match &r.data {
                                RData::TXT(txt) => Some(
                                    txt.txt_data.iter().flat_map(|s| s.iter().copied()).collect(),
                                ),
                                _ => None,
                            })
                            .collect();
                        let outcome = parse(
                            strings.iter().map(Vec::as_slice),
                            response.metadata.authentic_data,
                        );
                        let ttl = match &outcome {
                            Ok(_) => txt.iter().map(|r| r.ttl).min().unwrap_or(0),
                            Err(_) => response.negative_ttl().unwrap_or(0),
                        };
                        (outcome, ttl)
                    }
                    ResponseCode::NXDomain => {
                        (Err(Negative::NoRecord), response.negative_ttl().unwrap_or(0))
                    }
                    code => return Err(Error::Dns(format!("{host}: {code}"))),
                }
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(none)))
                if matches!(none.response_code, ResponseCode::NXDomain | ResponseCode::NoError) =>
            {
                (Err(Negative::NoRecord), none.negative_ttl.unwrap_or(0))
            }
            Err(e) => return Err(Error::Dns(e.to_string())),
        };
        self.cache().put(host, outcome.clone(), ttl, Instant::now());
        outcome.map_err(|n| n.error(host))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn key() -> PublicKey {
        weft_core::SecretKey::from_seed([9; 32]).public()
    }

    fn record(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    fn binding(n: u8) -> Binding {
        Binding { author: weft_core::SecretKey::from_seed([n; 32]).public(), authentic: n % 2 == 0 }
    }

    #[test]
    fn cache_honours_a_clamped_ttl() {
        let mut cache = Cache::default();
        let t0 = Instant::now();
        assert!(cache.get("a.example", t0).is_none());
        cache.put("a.example", Ok(binding(1)), 1, t0);
        assert_eq!(cache.get("a.example", t0 + Duration::from_secs(59)), Some(Ok(binding(1))));
        assert!(cache.get("a.example", t0 + Duration::from_secs(61)).is_none());
        assert!(cache.get("a.example", t0).is_none());
        cache.put("b.example", Ok(binding(2)), 300, t0);
        assert_eq!(cache.get("b.example", t0 + Duration::from_secs(299)), Some(Ok(binding(2))));
        assert!(cache.get("b.example", t0 + Duration::from_secs(301)).is_none());
        cache.put("c.example", Ok(binding(3)), u32::MAX, t0);
        assert_eq!(cache.get("c.example", t0 + Duration::from_secs(3599)), Some(Ok(binding(3))));
        assert!(cache.get("c.example", t0 + Duration::from_secs(3601)).is_none());
        cache.put("d.example", Ok(binding(4)), 120, t0);
        cache.put("d.example", Ok(binding(5)), 120, t0 + Duration::from_secs(100));
        assert_eq!(cache.get("d.example", t0 + Duration::from_secs(219)), Some(Ok(binding(5))));
    }

    #[test]
    fn cache_remembers_a_miss_for_the_negative_ttl() {
        let mut cache = Cache::default();
        let t0 = Instant::now();
        cache.put("none.example", Err(Negative::NoRecord), 0, t0);
        assert_eq!(
            cache.get("none.example", t0 + Duration::from_secs(59)),
            Some(Err(Negative::NoRecord))
        );
        assert!(cache.get("none.example", t0 + Duration::from_secs(61)).is_none());
        cache.put("bad.example", Err(Negative::Binding("not a key address")), 900, t0);
        assert_eq!(
            cache.get("bad.example", t0 + Duration::from_secs(899)),
            Some(Err(Negative::Binding("not a key address")))
        );
        assert!(cache.get("bad.example", t0 + Duration::from_secs(901)).is_none());
        assert!(matches!(
            Negative::NoRecord.error("none.example"),
            Error::Dns(why) if why == "no _weft record at none.example"
        ));
        assert!(matches!(Negative::Binding("x").error("bad.example"), Error::Binding("x")));
    }

    #[test]
    fn cache_evicts_the_soonest_expiry_when_full() {
        let mut cache = Cache::default();
        let t0 = Instant::now();
        for i in 0..MAX_ENTRIES {
            cache.put(&format!("h{i}.example"), Ok(binding(1)), 60 + u32::try_from(i).unwrap(), t0);
        }
        assert_eq!(cache.entries.len(), MAX_ENTRIES);
        cache.put("late.example", Ok(binding(2)), 3600, t0);
        assert_eq!(cache.entries.len(), MAX_ENTRIES);
        assert!(cache.get("h0.example", t0).is_none());
        assert_eq!(cache.get("h1.example", t0), Some(Ok(binding(1))));
        assert_eq!(cache.get("late.example", t0), Some(Ok(binding(2))));
        cache.put("fresh.example", Ok(binding(3)), 60, t0 + Duration::from_secs(4000));
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn one_record_binds() {
        let key = key();
        let txt = [record("v=spf1 -all"), record(&format!("weft={}", key.address()))];
        let binding = parse(txt.iter().map(Vec::as_slice), true).unwrap();
        assert_eq!(binding, Binding { author: key, authentic: true });
        let binding = parse(txt.iter().map(Vec::as_slice), false).unwrap();
        assert!(!binding.authentic);
    }

    #[test]
    fn missing_and_duplicate_records_reject() {
        let key = key();
        assert!(matches!(
            parse([record("v=spf1")].iter().map(Vec::as_slice), true),
            Err(Negative::Binding("no weft record"))
        ));
        let two = [
            record(&format!("weft={}", key.address())),
            record(&format!("weft={}", key.address())),
        ];
        assert!(matches!(
            parse(two.iter().map(Vec::as_slice), true),
            Err(Negative::Binding("more than one weft record"))
        ));
    }

    #[test]
    fn malformed_values_reject() {
        let hash = Address::of(b"page");
        assert!(matches!(
            parse([record(&format!("weft={hash}"))].iter().map(Vec::as_slice), true),
            Err(Negative::Binding("not a key address"))
        ));
        assert!(matches!(
            parse([record("weft=notanaddress")].iter().map(Vec::as_slice), true),
            Err(Negative::Binding("not an address"))
        ));
        let mut bad = record("weft=");
        bad.push(0xff);
        assert!(matches!(
            parse([bad].iter().map(Vec::as_slice), true),
            Err(Negative::Binding("not utf-8"))
        ));
        let key = key();
        assert!(matches!(
            parse([record(&format!("weft= {}", key.address()))].iter().map(Vec::as_slice), true),
            Err(Negative::Binding("not an address"))
        ));
        assert!(matches!(
            parse([record(&format!("WEFT={}", key.address()))].iter().map(Vec::as_slice), true),
            Err(Negative::Binding("no weft record"))
        ));
    }

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_resolver::proto::rr::Record;
    use hickory_resolver::proto::rr::rdata::{SOA, TXT};

    fn soa(minimum: u32) -> Record {
        let zone = Name::from_ascii("example.").unwrap();
        let soa = SOA::new(zone.clone(), zone.clone(), 1, 60, 60, 60, minimum);
        Record::from_rdata(zone, 300, RData::SOA(soa))
    }

    fn txt(name: &Name, ttl: u32, value: &str) -> Record {
        Record::from_rdata(name.clone(), ttl, RData::TXT(TXT::new(vec![value.to_owned()])))
    }

    fn answer(query: &Message) -> Message {
        let q = query.queries.first().unwrap();
        let name = q.name().clone();
        let host = name.to_ascii();
        let mut r = Message::response(query.metadata.id, query.metadata.op_code);
        r.metadata.recursion_desired = true;
        r.metadata.recursion_available = true;
        r.add_query(q.clone());
        let bound = format!("weft={}", key().address());
        match host.as_str() {
            "_weft.none.example." => {
                r.metadata.response_code = ResponseCode::NXDomain;
                r.add_authority(soa(120));
            }
            "_weft.empty.example." => {
                r.add_authority(soa(90));
            }
            "_weft.two.example." => {
                r.add_answer(txt(&name, 600, &bound));
                r.add_answer(txt(&name, 600, &bound));
                r.add_authority(soa(75));
            }
            "_weft.bad.example." => {
                r.add_answer(txt(&name, 600, "weft=nonsense"));
            }
            "_weft.good.example." => {
                r.metadata.authentic_data = true;
                r.add_answer(txt(&name, 500, "v=spf1 -all"));
                r.add_answer(txt(&name, 200, &bound));
            }
            _ => r.metadata.response_code = ResponseCode::ServFail,
        }
        r
    }

    async fn fake() -> (SocketAddr, Arc<AtomicUsize>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let asked = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&asked);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, from) = socket.recv_from(&mut buf).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let query = Message::from_vec(&buf[..n]).unwrap();
                socket.send_to(&answer(&query).to_vec().unwrap(), from).await.unwrap();
            }
        });
        (addr, asked)
    }

    #[tokio::test]
    async fn a_fake_name_server_drives_every_outcome() {
        let (addr, asked) = fake().await;
        let dns = Dns::udp(addr).unwrap();

        let binding = dns.lookup("good.example").await.unwrap();
        assert_eq!(binding, Binding { author: key(), authentic: true });
        assert!(dns.cache().entries["good.example"].1 - Instant::now() > MIN_TTL);
        assert!(dns.cache().entries["good.example"].1 - Instant::now() <= Duration::from_secs(200));

        for host in ["none.example", "empty.example"] {
            let err = dns.lookup(host).await.unwrap_err();
            assert!(err.to_string().contains("no _weft record"), "{host}: {err}");
            let cached = dns.cache().entries[host].clone();
            assert!(matches!(cached.0, Err(Negative::NoRecord)));
        }
        let none = dns.cache().entries["none.example"].1;
        assert!(
            none - Instant::now() > Duration::from_secs(110),
            "the SOA minimum is the miss TTL"
        );
        assert!(none - Instant::now() <= Duration::from_secs(120));
        let empty = dns.cache().entries["empty.example"].1;
        assert!(empty - Instant::now() <= Duration::from_secs(90));

        assert!(matches!(dns.lookup("two.example").await.unwrap_err(), Error::Binding(_)));
        assert!(matches!(dns.lookup("bad.example").await.unwrap_err(), Error::Binding(_)));
        assert!(matches!(dns.cache().entries["two.example"].0, Err(Negative::Binding(_))));
        let bad = dns.cache().entries["bad.example"].1;
        assert!(bad - Instant::now() >= Duration::from_secs(59), "no SOA clamps to the floor");

        let before = asked.load(Ordering::SeqCst);
        dns.lookup("good.example").await.unwrap();
        dns.lookup("none.example").await.unwrap_err();
        dns.lookup("two.example").await.unwrap_err();
        assert_eq!(asked.load(Ordering::SeqCst), before, "hits and misses come from the cache");

        assert!(matches!(dns.lookup("fail.example").await.unwrap_err(), Error::Dns(_)));
        assert!(matches!(dns.lookup("fail.example").await.unwrap_err(), Error::Dns(_)));
        assert_eq!(asked.load(Ordering::SeqCst), before + 2, "errors are never cached");
        assert!(!dns.cache().entries.contains_key("fail.example"));
    }
}
