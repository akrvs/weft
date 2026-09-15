#!/bin/sh
set -eu

OCI=${WEFT_OCI:-podman}
OUT=${2:-${XDG_RUNTIME_DIR:-/tmp}/weft-lnd}
NET=weft-lnd
BTC=weft-btc
RELAY=weft-lnd-relay
PAYER=weft-lnd-payer
BTC_IMAGE=docker.io/polarlightning/bitcoind:29.0
LND_IMAGE=docker.io/lightninglabs/lnd:v0.19.2-beta
RELAY_REST=18081
PAYER_REST=18082
LNCLI="lncli --network=regtest"
BTCCLI="bitcoin-cli -regtest -rpcuser=weft -rpcpassword=weft"

down() {
  for c in "$RELAY" "$PAYER" "$BTC"; do "$OCI" rm -f "$c" >/dev/null 2>&1 || true; done
  "$OCI" network rm -f "$NET" >/dev/null 2>&1 || true
}

field() {
  sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" | head -n 1
}

wait_for() {
  tries=0
  until "$@" >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 120 ] || { echo "gave up waiting for: $*" >&2; exit 1; }
    sleep 1
  done
}

lnd_up() {
  "$OCI" run -d --name "$1" --network "$NET" -p "127.0.0.1:$2:8080" "$LND_IMAGE" \
    --bitcoin.regtest --bitcoin.node=bitcoind \
    --bitcoind.rpchost="$BTC:18443" --bitcoind.rpcuser=weft --bitcoind.rpcpass=weft \
    --bitcoind.zmqpubrawblock="tcp://$BTC:28332" --bitcoind.zmqpubrawtx="tcp://$BTC:28333" \
    --noseedbackup --restlisten=0.0.0.0:8080 --rpclisten=0.0.0.0:10009 --listen=0.0.0.0:9735 \
    --tlsextradomain="$1" --tlsextraip=127.0.0.1 --externalip="$1" \
    --debuglevel=error --nobootstrap >/dev/null
}

case "${1:-up}" in
  down) down; exit 0 ;;
  up) ;;
  *) echo "usage: lnd.sh [up [dir] | down]" >&2; exit 2 ;;
esac

down
"$OCI" network create "$NET" >/dev/null
"$OCI" run -d --name "$BTC" --network "$NET" "$BTC_IMAGE" \
  -regtest -server -txindex -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
  -rpcuser=weft -rpcpassword=weft -fallbackfee=0.0002 \
  -zmqpubrawblock=tcp://0.0.0.0:28332 -zmqpubrawtx=tcp://0.0.0.0:28333 >/dev/null
wait_for "$OCI" exec "$BTC" $BTCCLI getblockchaininfo
lnd_up "$RELAY" "$RELAY_REST"
lnd_up "$PAYER" "$PAYER_REST"
wait_for "$OCI" exec "$RELAY" $LNCLI getinfo
wait_for "$OCI" exec "$PAYER" $LNCLI getinfo

PAYER_ADDR=$("$OCI" exec "$PAYER" $LNCLI newaddress p2wkh | field address)
"$OCI" exec "$BTC" $BTCCLI generatetoaddress 110 "$PAYER_ADDR" >/dev/null
synced() { "$OCI" exec "$1" $LNCLI getinfo | grep -q '"synced_to_chain": *true'; }
wait_for synced "$RELAY"
wait_for synced "$PAYER"
funded() { "$OCI" exec "$PAYER" $LNCLI walletbalance | grep -q '"confirmed_balance": *"[1-9]'; }
wait_for funded

RELAY_KEY=$("$OCI" exec "$RELAY" $LNCLI getinfo | field identity_pubkey)
"$OCI" exec "$PAYER" $LNCLI connect "$RELAY_KEY@$RELAY:9735" >/dev/null 2>&1 || true
"$OCI" exec "$PAYER" $LNCLI openchannel --node_key="$RELAY_KEY" --local_amt=1000000 >/dev/null
"$OCI" exec "$BTC" $BTCCLI generatetoaddress 6 "$PAYER_ADDR" >/dev/null
active() { "$OCI" exec "$PAYER" $LNCLI listchannels | grep -q '"active": *true'; }
wait_for active

umask 077
rm -rf "$OUT"
mkdir -p "$OUT"
LND_DATA=/root/.lnd/data/chain/bitcoin/regtest
"$OCI" cp "$RELAY:/root/.lnd/tls.cert" "$OUT/lnd.pem"
"$OCI" cp "$RELAY:$LND_DATA/invoice.macaroon" "$OUT/lnd.macaroon"
"$OCI" cp "$PAYER:/root/.lnd/tls.cert" "$OUT/payer.pem"
"$OCI" cp "$PAYER:$LND_DATA/admin.macaroon" "$OUT/payer.macaroon"
printf 'https://127.0.0.1:%s\n' "$RELAY_REST" > "$OUT/url"
printf 'https://127.0.0.1:%s\n' "$PAYER_REST" > "$OUT/payer.url"
chmod 600 "$OUT"/*

echo "regtest up, credentials in $OUT"
echo "WEFT_LND=$OUT cargo test -p weft-relay --test lnd -- --ignored"
echo "$0 down"
