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
geometry() { hyprctl clients -j | jq -r --argjson pid "$1" '.[] | select(.pid == $pid) | "\(.at[0]),\(.at[1]) \(.size[0])x\(.size[1])"'; }
shot() { grim -g "$(geometry "$1")" "$2"; }
