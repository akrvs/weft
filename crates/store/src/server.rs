use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;
use weft_core::{PublicKey, Record};

use crate::wire::{self, Request, Response};
use crate::{Error, Gate, Result};

pub const IDLE: Duration = Duration::from_secs(60);

pub async fn serve(gate: Arc<Gate>, listener: UnixListener) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            let _ = handle(&gate, stream).await;
        });
    }
}

fn nonce() -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).map_err(|e| Error::Io(e.to_string()))?;
    Ok(out)
}

async fn next(stream: &mut UnixStream) -> Result<Option<Request>> {
    let Some(frame) =
        timeout(IDLE, wire::recv(stream)).await.map_err(|_| Error::Wire("idle"))??
    else {
        return Ok(None);
    };
    Request::decode(&frame).map(Some)
}

async fn reply(stream: &mut UnixStream, response: &Response) -> Result<()> {
    wire::send(stream, &response.encode()).await
}

async fn handle(gate: &Gate, mut stream: UnixStream) -> Result<()> {
    let nonce = nonce()?;
    reply(&mut stream, &Response::Hello { nonce }).await?;
    let app = match next(&mut stream).await {
        Ok(Some(Request::Auth { app, sig })) => match Gate::verify_auth(&app, &nonce, &sig) {
            Ok(()) => app,
            Err(e) => return refuse(&mut stream, &e).await,
        },
        Ok(Some(_)) => return refuse(&mut stream, &Error::Refused("auth first")).await,
        Ok(None) => return Ok(()),
        Err(e) => return refuse(&mut stream, &e).await,
    };
    reply(&mut stream, &Response::Ok).await?;
    loop {
        let response = match next(&mut stream).await {
            Ok(Some(request)) => answer(gate, &app, request),
            Ok(None) => return Ok(()),
            Err(e) => return refuse(&mut stream, &e).await,
        };
        reply(&mut stream, &response).await?;
    }
}

async fn refuse(stream: &mut UnixStream, e: &Error) -> Result<()> {
    reply(stream, &Response::Error { why: e.to_string() }).await
}

fn answer(gate: &Gate, app: &PublicKey, request: Request) -> Response {
    let result = match request {
        Request::Auth { .. } => Err(Error::Refused("already authenticated")),
        Request::List { kind } => {
            gate.list(app, &kind).map(|addresses| Response::List { addresses })
        }
        Request::Get { address } => gate.get(app, &address).map(|record| Response::Get { record }),
        Request::Put { kind, body, refs } => {
            gate.put(app, &kind, body, refs).map(|address| Response::Put { address })
        }
        Request::Login { challenge } => {
            gate.login(app, &challenge).map(|proof| Response::Login { proof })
        }
        Request::Kinds => gate.kinds(app).map(|kinds| Response::Kinds { kinds }),
        Request::Grants => gate.grants(app).map(|records| Response::Grants {
            records: records.iter().map(Record::to_bytes).collect(),
        }),
        Request::Revoke { grant } => {
            gate.revoke(app, grant).map(|address| Response::Put { address })
        }
        Request::Publish { body, name } => {
            gate.publish(app, body, name.as_deref()).map(|records| Response::Publish {
                records: records.iter().map(Record::to_bytes).collect(),
            })
        }
        Request::Record { address } => gate.record(app, address).map(found),
        Request::Manifest { author } => gate.manifest(app, &author).map(found),
        Request::Pointers { author, name } => gate.pointers(app, &author, &name).map(|records| {
            Response::Records { records: records.iter().map(Record::to_bytes).collect() }
        }),
        Request::Blob { address, offset } => gate.blob(app, &address, offset).map(|b| match b {
            Some((total, chunk)) => Response::Blob { total, chunk },
            None => Response::Missing,
        }),
        Request::Keep { record } => gate.keep(app, &record).map(|()| Response::Ok),
    };
    result.unwrap_or_else(|e| Response::Error { why: e.to_string() })
}

fn found(record: Option<Vec<u8>>) -> Response {
    record.map_or(Response::Missing, |record| Response::Get { record })
}
