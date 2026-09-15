#!/usr/bin/env bash
set -euo pipefail
[[ -z ${SMOKE_TRACE:-} ]] || set -x

repo=$(cd "$(dirname "$0")/../.." && pwd)
bin=$repo/target/release
run=${XDG_RUNTIME_DIR:-/tmp}/weft-smoke-$$
sock=$run/drive.sock
pids=()

cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$run"
}
trap cleanup EXIT

mkdir -m 700 -p "$run"
export WEFT_NET=local WEFT_PASSPHRASE='correct horse'

js() { printf '%s' "$1" | socat -t 70 - "UNIX-CONNECT:$sock"; }
ok() { js "$1" | jq -er '.ok'; }
expect() {
    local got
    got=$(ok "$1")
    [[ "$got" == "$2" ]] || { echo "expected $2, got $got for $1" >&2; exit 1; }
}
wait_js() {
    for _ in $(seq 1 300); do
        if [[ $(ok "$1") == "true" ]]; then return; fi
        sleep 0.2
    done
    echo "timed out waiting for $1" >&2
    exit 1
}
set_value() { ok "(() => { const e = document.getElementById('$1'); e.value = $2; e.dispatchEvent(new Event('input', { bubbles: true })); return true; })()" >/dev/null; }
click() { ok "(() => { document.getElementById('$1').click(); return true; })()" >/dev/null; }
submit() { ok "(() => { document.getElementById('$1').requestSubmit(); return true; })()" >/dev/null; }
shot() {
    local geometry
    geometry=$(hyprctl clients -j | jq -r --argjson pid "$browser" '.[] | select(.pid == $pid) | "\(.at[0]),\(.at[1]) \(.size[0])x\(.size[1])"')
    grim -g "$geometry" "$1"
}

ui=$repo/crates/browser/ui
[[ $ui/dist/main.js -nt $ui/src/main.ts ]] || npm run --prefix "$ui" build >/dev/null
cargo build --release -p weft -p weft-relay -p weft-bank -p weft-store -p weft-gateway --manifest-path "$repo/Cargo.toml"
cargo build --release -p weft-browser --features drive --manifest-path "$repo/Cargo.toml"

export PATH=$bin:$PATH

root_a=$(WEFT_HOME=$run/a weft init | head -1)
WEFT_HOME=$run/a weft device add laptop >/dev/null
root_b=$(WEFT_HOME=$run/b weft init | head -1)
WEFT_HOME=$run/b weft device add laptop >/dev/null

weft-relay --dir "$run/relay" init >/dev/null
weft-relay --dir "$run/relay" allow "$root_a" >/dev/null
weft-bank --dir "$run/bank" init >/dev/null
weft-relay --dir "$run/relay" bank add "$(weft-bank --dir "$run/bank" whoami)" >/dev/null
weft-relay --dir "$run/relay" rate 1 >/dev/null
weft-relay --dir "$run/relay" sats 10 >/dev/null
weft-relay --dir "$run/relay" node fake >/dev/null
weft-relay --dir "$run/relay" serve >"$run/relay.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 100); do grep -q '^online' "$run/relay.log" && break; sleep 0.2; done
relay_id=$(head -1 "$run/relay.log")
entry=$(awk '/^entry/ { print $2 }' "$run/relay.log")
entry=${entry:-$relay_id}
WEFT_HOME=$run/a weft relay add "$entry" >/dev/null
WEFT_HOME=$run/b weft relay add "$entry" >/dev/null

address_of() { local line; line=$(tail -1); line=${line##*/}; echo "${line%.weft}"; }
WEFT_HOME=$run/a weft manifest >/dev/null
printf '# Blog\n\nposts go here\n' >"$run/blog.md"
blog=$(WEFT_HOME=$run/a weft sign "$run/blog.md" --as laptop | address_of)
WEFT_HOME=$run/a weft point blog "$blog" --as laptop >/dev/null
head -c 3000000 /dev/urandom >"$run/big.bin"
big=$(WEFT_HOME=$run/a weft sign "$run/big.bin" --kind file --as laptop | address_of)
printf '# Hello from a\n\nread the [blog](weft:%s/blog) or pull the [big file](weft:%s).\n' "$root_a" "$big" >"$run/home.md"
home_a=$(WEFT_HOME=$run/a weft sign "$run/home.md" --as laptop | address_of)
WEFT_HOME=$run/a weft point home "$home_a" --as laptop >/dev/null
WEFT_HOME=$run/a weft push >/dev/null
WEFT_HOME=$run/b weft manifest >/dev/null
for _ in $(seq 1 50); do
    WEFT_HOME=$run/b weft fetch "$big" --out "$run/copy.bin" >/dev/null 2>&1 && break
    sleep 0.5
done
cmp -s "$run/big.bin" "$run/copy.bin" || { echo "the relay never served the blob" >&2; exit 1; }
voucher=$(weft-bank --dir "$run/bank" mint --to "$relay_id" --cents 40 --out "$run/v.bin" | tail -1)

root_c=$(WEFT_HOME=$run/c weft init | head -1)
WEFT_HOME=$run/c weft relay add "$entry" >/dev/null
WEFT_HOME=$run/c weft manifest >/dev/null
printf '# Paid over lightning\n' >"$run/lit.md"
lit=$(WEFT_HOME=$run/c weft sign "$run/lit.md" | address_of)
WEFT_HOME=$run/c weft invoice "$lit" --days 2 >"$run/invoice.txt"
grep -q '^invoice  2 cents  20 sats' "$run/invoice.txt"
hash=$(awk '/^hash/ { print $2 }' "$run/invoice.txt")
preimage=$(cat "$run/relay/data/preimages/$hash")
WEFT_HOME=$run/c weft push "$lit" --preimage "$preimage" --days 2 >/dev/null
WEFT_HOME=$run/c weft receipts | grep -q "lightning  1 records"
! WEFT_HOME=$run/c weft push "$lit" --preimage "$preimage" --days 2 >/dev/null 2>&1
WEFT_HOME=$run/b weft fetch "$lit" --out "$run/lit.copy" >/dev/null 2>&1

WEFT_HOME=$run/b WEFT_DRIVE=$sock weft-browser "$root_a/home" >"$run/browser.log" 2>&1 &
browser=$!
pids+=($browser)
for _ in $(seq 1 100); do [[ -S $sock ]] && break; sleep 0.2; done
sleep 1

wait_js "!document.getElementById('start').hidden"
set_value start-device "'laptop'"
set_value start-pass "'$WEFT_PASSPHRASE'"
submit start
wait_js "document.getElementById('content').querySelector('h1')?.textContent === 'Hello from a'"
click store-close
expect "document.getElementById('address').value" "$root_a/home"
expect "document.getElementById('status').textContent" "signed by an authorized device"
expect "document.getElementById('p-name').textContent" "$root_a/home"
expect "document.querySelector('#content a[href=\"weft:$root_a/blog\"]')?.textContent" "blog"

expect "(() => { window.__pulls = []; return window.__TAURI__.event.listen('pull', (e) => window.__pulls.push(e.payload)).then(() => true); })()" true
ok "(() => { document.querySelector('#content a[href=\"weft:$root_a/blog\"]').click(); return true; })()" >/dev/null
wait_js "document.getElementById('content').querySelector('h1')?.textContent === 'Blog'"
expect "document.getElementById('address').value" "$root_a/blog"

click back
wait_js "document.getElementById('content').querySelector('h1')?.textContent === 'Hello from a'"
ok "(() => { document.querySelector('#content a[href=\"weft:$big\"]').click(); return true; })()" >/dev/null
wait_js "document.getElementById('blob') !== null"
expect "document.getElementById('content').textContent.includes('save to downloads')" true
expect "window.__pulls.length > 0 && window.__pulls.every((p) => p.total === 3000000)" true
expect "window.__pulls.at(-1).done" 3000000

click back
wait_js "document.getElementById('content').querySelector('h1')?.textContent === 'Hello from a'"
click prov-line
wait_js "!document.getElementById('prov-detail').hidden"
ok "(() => { document.documentElement.dataset.theme = 'light'; return true; })()" >/dev/null
sleep 0.5
shot "$repo/docs/browser-home-light.png"
ok "(() => { document.documentElement.dataset.theme = 'dark'; return true; })()" >/dev/null
sleep 0.5
shot "$repo/docs/browser-home.png"
ok "(() => { delete document.documentElement.dataset.theme; return true; })()" >/dev/null
cat "$ui/index.html" "$ui/style.css" "$ui/src/main.ts" | sha256sum | cut -d' ' -f1 >"$repo/docs/browser-home.sha256"

click star
wait_js "document.getElementById('star').textContent === 'bookmarked'"
click bookmarks-toggle
wait_js "document.getElementById('bookmarks-list').textContent.includes('$root_a/home')"
click bookmarks-close
click history-toggle
wait_js "document.getElementById('history-list').textContent.includes('$root_a/blog')"
click history-close

click compose-toggle
wait_js "!document.getElementById('compose').hidden && document.getElementById('price').textContent.includes('1 cents')"
set_value markdown "'# Notes from b\\n\\nwritten in compose'"
wait_js "document.getElementById('preview').querySelector('h1')?.textContent === 'Notes from b'"
set_value name "'notes'"
set_value days "'7'"
set_value payment "'$voucher'"
submit publish
wait_js "/stored [1-9]/.test(document.getElementById('publish-result').textContent)"
expect "document.getElementById('publish-result').textContent.includes('rejected 0')" true
expect "document.getElementById('publish-result').textContent.includes('40 cents until')" true

set_value markdown "'# Lit from b\\n\\npaid over lightning'"
set_value name "'lit'"
set_value days "'3'"
click invoice
wait_js "/^hash [0-9a-f]{64}$/m.test(document.getElementById('invoice-text').textContent)"
expect "document.getElementById('invoice-text').textContent.startsWith('6 cents  60 sats  expires ')" true
hash=$(ok "document.getElementById('invoice-text').textContent.match(/hash ([0-9a-f]{64})/)[1]")
set_value payment "'$(cat "$run/relay/data/preimages/$hash")'"
submit publish
wait_js "/stored [1-9]/.test(document.getElementById('publish-result').textContent)"
expect "document.getElementById('publish-result').textContent.includes('rejected 0')" true
expect "document.getElementById('publish-result').textContent.includes('lightning until')" true
click compose-toggle

click store-toggle
wait_js "document.getElementById('store-names').textContent.includes('notes')"
expect "document.getElementById('store-names').textContent.includes('seq 1')" true
set_value repoint-name "'notes'"
set_value repoint-target "'$blog'"
submit repoint
wait_js "document.getElementById('store-names').textContent.includes('seq 2')"
expect "document.getElementById('store-names').textContent.includes('$blog')" true
click store-close

set_value address "'$root_b/notes'"
submit go
wait_js "document.getElementById('content').querySelector('h1')?.textContent === 'Blog'"

port=$((20000 + RANDOM % 20000))
WEFT_HOME=$run/b weft-gateway --bind "127.0.0.1:$port" >"$run/gateway.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 100); do curl -sf -o /dev/null "http://127.0.0.1:$port/" && break; sleep 0.2; done
location=$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$port/login")
[[ $location == http://127.0.0.1:$port/login/* ]]
challenge=$(curl -s "$location" | grep -o 'weft:login?c=[A-Za-z0-9_-]*' | head -1)
[[ -n $challenge ]]
set_value address "'$challenge'"
submit go
wait_js "document.getElementById('login').open"
expect "document.getElementById('login-service').textContent" "http://127.0.0.1:$port"
submit login-form
wait_js "document.getElementById('login-result').textContent.includes('logged in at')"
expect "document.getElementById('login-result').textContent.includes('$root_b')" true
click login-cancel
curl -si "$location" >"$run/claim.txt"
grep -qi '^set-cookie: weft_session=' "$run/claim.txt"
grep -q "$root_b" "$run/claim.txt"
curl -s -o /dev/null -w '%{http_code}' "$location" | grep -q '^403$'

echo "smoke: ok"
for shot in browser-home browser-home-light; do
    echo "smoke: $(du -h "$repo/docs/$shot.png" | cut -f1) docs/$shot.png"
done
