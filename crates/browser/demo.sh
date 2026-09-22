#!/usr/bin/env bash
set -euo pipefail
[[ -z ${DEMO_TRACE:-} ]] || set -x

for tool in grim hyprctl socat jq agg ffmpeg firefox; do
    command -v "$tool" >/dev/null || { echo "demo needs $tool" >&2; exit 1; }
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
bin=$repo/target/release
out=$repo/target/demo
run=${XDG_RUNTIME_DIR:-/tmp}/weft-demo-$$
sock=$run/drive.sock
pids=()
font=${DEMO_FONT:-Cascadia Mono}
bg=0x0E1319
fg=0xE7ECF2
accent=0x56BDC3
width=1280
height=800

cleanup() {
    [[ -z ${grabber:-} ]] || kill "$grabber" 2>/dev/null || true
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$run"
}
trap cleanup EXIT

mkdir -m 700 -p "$run" "$run/frames" "$run/cards"
rm -rf "$out"
mkdir -p "$out"
export WEFT_NET=local WEFT_PASSPHRASE='correct horse'
source "$repo/crates/browser/drive.sh"

ui=$repo/crates/browser/ui
[[ $ui/dist/main.js -nt $ui/src/main.ts ]] || npm run --prefix "$ui" build >/dev/null
cargo build --release -p weft -p weft-relay -p weft-bank -p weft-store -p weft-gateway --manifest-path "$repo/Cargo.toml"
cargo build --release -p weft-browser --features drive --manifest-path "$repo/Cargo.toml"
export PATH=$bin:$PATH

cast=$run/terminal.cast
cast_ms=0
printf '{"version": 2, "width": 96, "height": 30, "title": "weft 0.1"}\n' >"$cast"
emit() {
    printf '[%d.%03d, "o", %s]\n' $((cast_ms / 1000)) $((cast_ms % 1000)) "$(jq -Rn --arg s "$1" '$s')" >>"$cast"
}
say() {
    cast_ms=$((cast_ms + 400))
    emit $'\e[2m'"# $1"$'\e[0m\r\n'
    cast_ms=$((cast_ms + 900))
}
typed() {
    local cmd=$1 i
    emit $'\e[1;36m$\e[0m '
    for ((i = 0; i < ${#cmd}; i++)); do
        cast_ms=$((cast_ms + 28))
        emit "${cmd:i:1}"
    done
    cast_ms=$((cast_ms + 350))
    emit $'\r\n'
}
shown() {
    local line
    while IFS= read -r line; do
        cast_ms=$((cast_ms + 40))
        emit "$line"$'\r\n'
    done
    cast_ms=$((cast_ms + 700))
}
cli() {
    local home=$1 display=$2
    shift 2
    typed "$display"
    WEFT_HOME=$run/$home "$@" 2>&1 | tee "$run/last" | shown
}
address_of() { local line; line=$(tail -1); line=${line##*/}; echo "${line%.weft}"; }

say "machine A: an identity, a device, a manifest"
cli a "weft init" weft init
root_a=$(head -1 "$run/last")
cli a "weft device add laptop" weft device add laptop
cli a "weft manifest" weft manifest

say "a relay you run, anywhere with a route"
typed "weft-relay init"
weft-relay --dir "$run/relay" init | shown
typed "weft-relay allow $root_a"
weft-relay --dir "$run/relay" allow "$root_a" | shown
weft-bank --dir "$run/bank" init >/dev/null
weft-relay --dir "$run/relay" bank add "$(weft-bank --dir "$run/bank" whoami)" >/dev/null
weft-relay --dir "$run/relay" rate 1 >/dev/null
weft-relay --dir "$run/relay" node fake >/dev/null
typed "weft-relay serve &"
weft-relay --dir "$run/relay" serve >"$run/relay.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 100); do grep -q '^online' "$run/relay.log" && break; sleep 0.2; done
shown <"$run/relay.log"
relay_id=$(head -1 "$run/relay.log")
entry=$(awk '/^entry/ { print $2 }' "$run/relay.log")
entry=${entry:-$relay_id}

say "machine A: sign a page, name it, push it"
printf '# Blog\n\nposts go here\n' >"$run/blog.md"
blog=$(WEFT_HOME=$run/a weft sign "$run/blog.md" --as laptop | address_of)
WEFT_HOME=$run/a weft point blog "$blog" --as laptop >/dev/null
head -c 3000000 /dev/urandom >"$run/big.bin"
big=$(WEFT_HOME=$run/a weft sign "$run/big.bin" --kind file --as laptop | address_of)
printf '# Hello from A\n\nThis page is signed by a device key, named by its blake3 hash, and served by a relay that cannot alter it.\n\nRead the [blog](weft:%s/blog) or pull a [3 MB file](weft:%s).\n' "$root_a" "$big" >"$run/home.md"
cli a "weft sign home.md --as laptop" weft sign "$run/home.md" --as laptop
home_a=$(address_of <"$run/last")
cli a "weft point home $home_a --as laptop" weft point home "$home_a" --as laptop
cli a "weft relay add $entry" weft relay add "$entry"
cli a "weft push" weft push

say "machine B: nothing shared but the relay id"
cli b "weft init" weft init
root_b=$(head -1 "$run/last")
WEFT_HOME=$run/b weft device add laptop >/dev/null
WEFT_HOME=$run/b weft manifest >/dev/null
cli b "weft relay add $entry" weft relay add "$entry"
cli b "weft resolve $root_a home --relay" weft resolve "$root_a" home --relay
typed "weft-browser $root_a/home"
cast_ms=$((cast_ms + 1500))
emit ""

voucher=$(weft-bank --dir "$run/bank" mint --to "$relay_id" --cents 40 --out "$run/v.bin" | tail -1)

agg --cols 96 --rows 30 --font-family "$font" --font-size 15 --theme 0e1319,e7ecf2,0e1319,c4453b,56bdc3,e4b04a,3b7ed6,a25fb5,56bdc3,b9c4d0,4c5966,e06c5a,8ed7db,f0c96a,6da3ef,c58ad5,8ed7db,ffffff \
    --idle-time-limit 2 "$cast" "$run/terminal.gif" >/dev/null 2>&1

frames_list=$run/frames.txt
grab() {
    local geometry=$1 i=0 last now
    last=$(date +%s.%N)
    while :; do
        now=$(date +%s.%N)
        if ((i > 0)); then printf 'duration %s\n' "$(awk -v a="$last" -v b="$now" 'BEGIN { printf "%.3f", b - a }')" >>"$frames_list"; fi
        printf "file '%s/frames/%05d.png'\n" "$run" "$i" >>"$frames_list"
        grim -g "$geometry" "$run/frames/$(printf %05d "$i").png" 2>/dev/null || true
        last=$now
        i=$((i + 1))
        sleep 0.1
    done
}
start_grab() {
    : >"$frames_list"
    grab "$1" &
    grabber=$!
}
stop_grab() {
    kill "$grabber" 2>/dev/null || true
    wait "$grabber" 2>/dev/null || true
    grabber=
    printf 'duration 1.5\n' >>"$frames_list"
    ffmpeg -loglevel error -y -f concat -safe 0 -i "$frames_list" -vf "scale=$width:$height:force_original_aspect_ratio=decrease,pad=$width:$height:(ow-iw)/2:(oh-ih)/2:color=$bg,fps=30,format=yuv420p" \
        -c:v libx264 -preset medium -crf 20 "$1"
    rm -f "$run"/frames/*.png
}
place() {
    local pid=$1
    for _ in $(seq 1 100); do
        [[ -n $(hyprctl clients -j | jq -r --argjson pid "$pid" '.[] | select(.pid == $pid) | .address') ]] && break
        sleep 0.1
    done
    hyprctl --batch "dispatch setfloating pid:$pid; dispatch resizewindowpixel exact $width $height,pid:$pid; dispatch movewindowpixel exact 200 120,pid:$pid" >/dev/null
    sleep 0.6
    geometry "$pid"
}
type_into() {
    local id=$1 text=$2 i
    for ((i = 1; i <= ${#text}; i++)); do
        set_value "$id" "$(jq -Rn --arg s "${text:0:i}" '$s')"
        sleep 0.03
    done
}
hold() { sleep "$1"; }

WEFT_HOME=$run/b WEFT_DRIVE=$sock weft-browser "$root_a/home" >"$run/browser.log" 2>&1 &
browser=$!
pids+=($browser)
for _ in $(seq 1 100); do [[ -S $sock ]] && break; sleep 0.2; done
geometry=$(place "$browser")
wait_js "!document.getElementById('start').hidden"
start_grab "$geometry"
hold 1
type_into start-device laptop
type_into start-pass "$WEFT_PASSPHRASE"
hold 0.5
submit start
wait_js "document.getElementById('content').querySelector('h1')?.textContent === 'Hello from A'"
hold 0.8
click store-close
hold 2.5
click prov-line
wait_js "!document.getElementById('prov-detail').hidden"
hold 4
click prov-line
hold 0.8
ok "(() => { document.querySelector('#content a[href=\"weft:$root_a/blog\"]').click(); return true; })()" >/dev/null
wait_js "document.getElementById('content').querySelector('h1')?.textContent === 'Blog'"
hold 2
click back
wait_js "document.getElementById('content').querySelector('h1')?.textContent === 'Hello from A'"
hold 1
ok "(() => { document.querySelector('#content a[href=\"weft:$big\"]').click(); return true; })()" >/dev/null
wait_js "document.getElementById('blob') !== null"
hold 2.5
click back
wait_js "document.getElementById('content').querySelector('h1')?.textContent === 'Hello from A'"
hold 1
stop_grab "$run/read.mp4"

start_grab "$geometry"
hold 0.8
click compose-toggle
wait_js "!document.getElementById('compose').hidden && document.getElementById('price').textContent.includes('1 cents')"
hold 1
type_into markdown $'# Notes from B\n\nWritten in the browser, signed by the daemon, pinned on a relay for a few cents.'
hold 1
type_into name notes
type_into days 7
hold 0.5
type_into payment "$voucher"
hold 1
submit publish
wait_js "/stored [1-9]/.test(document.getElementById('publish-result').textContent)"
hold 3.5
click compose-toggle
hold 0.5
set_value address "''"
type_into address "$root_b/notes"
hold 0.4
submit go
wait_js "document.getElementById('content').querySelector('h1')?.textContent === 'Notes from B'"
hold 2.5
click store-toggle
wait_js "document.getElementById('store-names').textContent.includes('notes')"
hold 3
click store-close
hold 1
stop_grab "$run/write.mp4"

port=$((20000 + RANDOM % 20000))
WEFT_HOME=$run/b weft-gateway --bind "127.0.0.1:$port" >"$run/gateway.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 100); do curl -sf -o /dev/null "http://127.0.0.1:$port/" && break; sleep 0.2; done
mkdir -p "$run/ff"
cat >"$run/ff/user.js" <<'EOF'
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("datareporting.policy.dataSubmissionPolicyBypassNotification", true);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.tabs.warnOnClose", false);
EOF
firefox --no-remote --new-instance --profile "$run/ff" --width $width --height $height "http://127.0.0.1:$port/$root_a/home" >"$run/firefox.log" 2>&1 &
ff=$!
pids+=($ff)
ff_geometry=$(place "$ff")
sleep 2
start_grab "$ff_geometry"
hold 5
stop_grab "$run/gateway.mp4"
kill "$ff" 2>/dev/null || true

card() {
    local file=$1 seconds=$2
    printf '%s' "$3" >"$file.title"
    printf '%s' "${4:-}" >"$file.sub"
    ffmpeg -loglevel error -y -f lavfi -i "color=c=$bg:s=${width}x${height}:d=$seconds:r=30" \
        -vf "drawtext=fontfile=$fontfile:textfile=$file.title:fontcolor=$fg:fontsize=52:x=(w-text_w)/2:y=(h-text_h)/2-40,drawtext=fontfile=$fontfile:textfile=$file.sub:fontcolor=$accent:fontsize=26:x=(w-text_w)/2:y=(h-text_h)/2+40" \
        -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p "$file"
}
fontfile=$(fc-match -f '%{file}' "$font")
card "$run/cards/title.mp4" 3.5 "weft 0.1" "sign here, fetch there, no shared server"
card "$run/cards/terminal.mp4" 2.5 "two machines and a relay" "the CLI"
card "$run/cards/read.mp4" 2.5 "machine B reads" "signed by A, served by the relay, verified here"
card "$run/cards/write.mp4" 2.5 "machine B publishes" "the browser signs nothing, the daemon does"
card "$run/cards/gateway.mp4" 2.5 "any browser" "the same page through a gateway"
card "$run/cards/end.mp4" 4 "github.com/akrvs/weft" "Apache-2.0"

ffmpeg -loglevel error -y -i "$run/terminal.gif" -vf "scale=$width:$height:force_original_aspect_ratio=decrease,pad=$width:$height:(ow-iw)/2:(oh-ih)/2:color=$bg,fps=30,format=yuv420p" \
    -c:v libx264 -preset medium -crf 20 "$run/terminal.mp4"

concat=$run/concat.txt
for part in cards/title cards/terminal terminal cards/read read cards/write write cards/gateway gateway cards/end; do
    printf "file '%s/%s.mp4'\n" "$run" "$part" >>"$concat"
done
ffmpeg -loglevel error -y -f concat -safe 0 -i "$concat" -c copy "$out/weft-0.1.mp4"
ffmpeg -loglevel error -y -i "$out/weft-0.1.mp4" -vf "fps=8,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" "$out/weft-0.1.gif"

echo "demo: ok"
for file in weft-0.1.mp4 weft-0.1.gif; do
    echo "demo: $(du -h "$out/$file" | cut -f1) $(ffprobe -v error -show_entries format=duration -of csv=p=0 "$out/$file" | cut -d. -f1)s target/demo/$file"
done
