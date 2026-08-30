#!/usr/bin/env bash
# selftest.sh - prove the sensor->witness statement round trip, offline.
#
# Touches neither DuckDNS nor Linode. It generates a throwaway key, signs a
# statement exactly as publish.sh does, hands it to sync.sh's own verify and
# parsing, and then checks that each way of lying about it is rejected.
#
# This exists because the two halves run on different machines and the failure
# mode is silent: a statement the witness cannot parse looks exactly like a
# tampered one, and a firewall that never moves looks exactly like an address
# that never changed. Both ends are exercised here, in one process.
#
#   infra/fw-autosync/selftest.sh
set -uo pipefail
cd "$(dirname "$0")"

pass=0 fail=0
ok()   { pass=$((pass+1)); printf '  ok    %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL  %s\n' "$1"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

command -v openssl >/dev/null || { echo "openssl required"; exit 2; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
openssl genpkey -algorithm ed25519 -out "$tmp/k" 2>/dev/null
openssl pkey -in "$tmp/k" -pubout -out "$tmp/k.pub" 2>/dev/null

# The witness side, with its file locations pointed at the sandbox. Sourcing is
# safe because of the BASH_SOURCE guard at the bottom of sync.sh.
export FWSYNC_PUB="$tmp/k.pub" FWSYNC_SEEN="$tmp/seen" FWSYNC_DUCKDNS_DOMAIN=x
# shellcheck disable=SC1091
source ./sync.sh

sign() { # $1 message -> base64 signature, exactly as publish.sh produces it
  printf '%s' "$1" > "$tmp/m"
  openssl pkeyutl -sign -inkey "$tmp/k" -rawin -in "$tmp/m" | base64 -w0
}

echo "signature"
msg="203.0.113.9 $(date +%s) deadbeefdeadbeefdeadbeefdeadbeef"
sig=$(sign "$msg")
verify "$msg" "$sig" && ok "a real statement verifies" || bad "a real statement verifies"
verify "203.0.113.10 $(date +%s) deadbeefdeadbeefdeadbeefdeadbeef" "$sig" \
  && bad "a changed address must not verify" || ok "a changed address is rejected"
verify "$msg" "$(printf 'AAAA' | base64 -w0)" \
  && bad "a garbage signature must not verify" || ok "a garbage signature is rejected"

# The attack that matters: the whole point of signing is that whoever controls
# the rendezvous cannot redirect the firewall at an address of their choosing.
openssl genpkey -algorithm ed25519 -out "$tmp/evil" 2>/dev/null
printf '%s' "198.51.100.66 $(date +%s) aaaa" > "$tmp/m"
evilsig=$(openssl pkeyutl -sign -inkey "$tmp/evil" -rawin -in "$tmp/m" | base64 -w0)
verify "198.51.100.66 $(date +%s) aaaa" "$evilsig" \
  && bad "a statement signed by another key must not verify" \
  || ok "a statement signed by another key is rejected"

echo "address sanity"
for good in 203.0.113.9 198.51.100.1; do
  sane_ip "$good" && ok "accepts $good" || bad "accepts $good"
done
for bogus in 10.0.0.5 192.168.1.1 127.0.0.1 169.254.1.1 not-an-ip; do
  sane_ip "$bogus" && bad "rejects $bogus" || ok "rejects $bogus"
done

echo "rendezvous parsing"
# What dig actually prints, including the case where a long TXT is split into
# quoted chunks. The statement's own spaces must survive; the quoting must not.
stmt="$msg|$sig"
rendezvous_get() { printf '"%s"\n' "$stmt"; }
check "a quoted TXT record round trips" "$(rendezvous_get | sed -e 's/" "//g' -e 's/^"//' -e 's/"$//' | tr -d '\n')" "$stmt"
split="\"${stmt:0:40}\" \"${stmt:40}\""
check "a split TXT record is rejoined" "$(printf '%s\n' "$split" | sed -e 's/" "//g' -e 's/^"//' -e 's/"$//' | tr -d '\n')" "$stmt"

echo "statement split"
m=${stmt%%|*}; s=${stmt#*|}
check "message half" "$m" "$msg"
check "signature half" "$s" "$sig"
read -r rip rts rnonce <<<"$m"
check "address parses" "$rip" "203.0.113.9"
[ -n "$rts" ] && [ -n "$rnonce" ] && ok "timestamp and nonce parse" || bad "timestamp and nonce parse"

echo "freshness"
MAX_AGE=600
now=$(date +%s)
fresh() { local ts=$1; (( now - ts <= MAX_AGE && ts - now <= MAX_AGE )); }
fresh "$now"            && ok "now is fresh"                 || bad "now is fresh"
fresh $((now - 300))    && ok "5 minutes old is fresh"       || bad "5 minutes old is fresh"
fresh $((now - 1200))   && bad "20 minutes old must be stale" || ok "20 minutes old is stale"
fresh $((now + 1200))   && bad "20 minutes ahead must be stale" || ok "a future timestamp is stale"

echo "replay guard"
: > "$SEEN"
spend "$rnonce"
grep -qxF "$rnonce" "$SEEN" && ok "a spent nonce is recorded" || bad "a spent nonce is recorded"
for i in $(seq 1 700); do echo "n$i" >> "$SEEN"; done
spend zzz
n=$(wc -l < "$SEEN")
[ "$n" -le 501 ] && ok "the nonce file stays bounded ($n lines)" \
                 || bad "the nonce file grew to $n lines"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
