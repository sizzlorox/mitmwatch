#!/usr/bin/env bash
# sync.sh - WITNESS side of fw-autosync.
#
# Fetch the sensor's signed IP statement, verify it, and - only if it checks out
# and the IP changed - move the Linode firewall's sensor rule to the new /32.
#
# Trust comes from the ed25519 signature, never from the channel. A tampered or
# replayed statement is rejected. The Linode token lives only here, scoped to
# firewalls, root-only. The firewall is defence-in-depth: even a bad update
# cannot get past the witness's pinned mTLS or key-only SSH.
set -euo pipefail

PUB="${FWSYNC_PUB:-/etc/mitmwatch/fwsync.pub}"          # sensor's ed25519 public key
TOKEN_FILE="${FWSYNC_TOKEN:-/etc/mitmwatch/linode-fw.token}"  # firewalls:read_write, root-only
SEEN="${FWSYNC_SEEN:-/var/lib/mitmwatch/fwsync.seen}"   # spent nonces (anti-replay)
FIREWALL_ID="${FWSYNC_FIREWALL_ID:-}"                   # numeric Linode firewall id
# Every inbound rule that should follow the sensor's address, space separated.
#
# Plural on purpose. This deployment pins two rules to the sensor - "ssh" and
# "witness-mtls" - and moving only one is its own lockout: the witness link
# comes back while SSH stays pinned to an address that no longer exists, so the
# next time anything needs a shell there is no way in but the serial console.
# FWSYNC_RULE_LABEL (singular) is still honoured for older configs.
RULE_LABELS="${FWSYNC_RULE_LABELS:-${FWSYNC_RULE_LABEL:-ssh witness-mtls}}"
MAX_AGE="${FWSYNC_MAX_AGE:-600}"                        # seconds a statement stays valid

# --- rendezvous: DuckDNS - mirror of publish.sh -----------------------------
# Read the statement out of a TXT record. See publish.sh for why DuckDNS, and
# why the channel does not have to be trusted: everything below this line treats
# the answer as hostile until the signature verifies.
#
# Only the TXT record is read. DuckDNS also holds an A record for the same name
# and using it would be the whole bug - the firewall must move only to an
# address this witness can verify a signature over.
DUCK_DOMAIN="${FWSYNC_DUCKDNS_DOMAIN:-}"      # label only, no .duckdns.org

rendezvous_get() {
  [[ -n $DUCK_DOMAIN ]] || die "set FWSYNC_DUCKDNS_DOMAIN"
  local raw
  raw=$(dig +short +time=5 +tries=2 TXT "${DUCK_DOMAIN}.duckdns.org" 2>/dev/null) || return 1
  [[ -n $raw ]] || return 1

  # dig prints each TXT record on its own line, quoted, and splits a string
  # longer than 255 bytes into several quoted chunks separated by a space on
  # that line. Take the first record, rejoin the chunks, and drop the enclosing
  # quotes - but nothing else. The statement's own single spaces are structural
  # ("ip ts nonce"), so a blanket whitespace strip would corrupt the message and
  # surface as a signature failure, which reads like tampering rather than a
  # parsing bug. A statement is ~150 bytes and should never be split; handling
  # it anyway costs one substitution.
  head -n1 <<<"$raw" | sed -e 's/" "//g' -e 's/^"//' -e 's/"$//' | tr -d '\n'
}

die() { echo "fw-sync: $*" >&2; exit 1; }

verify() {
  # $1 msg  $2 base64 sig -> 0 if the signature is the sensor's. Ed25519 is
  # one-shot: the message must be a file, not piped on stdin.
  local mf sf; mf=$(mktemp); sf=$(mktemp)
  printf '%s' "$1" > "$mf"
  printf '%s' "$2" | base64 -d > "$sf" 2>/dev/null || { rm -f "$mf" "$sf"; return 1; }
  openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$mf" -sigfile "$sf" >/dev/null 2>&1
  local rc=$?; rm -f "$mf" "$sf"; return $rc
}

sane_ip() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && [[ $1 != 10.* && $1 != 192.168.* && $1 != 127.* && $1 != 169.254.* ]]; }

# spend records a nonce as used, and keeps the file bounded.
#
# A nonce is only ever useful inside MAX_AGE, so remembering the last few
# hundred is far more history than the replay guard can need - and an
# append-only file on a small VPS that grows every two minutes forever is a
# slow-motion disk-full bug in the component whose whole job is to still be
# working months from now.
spend() {
  echo "$1" >> "$SEEN"
  local keep; keep=$(tail -n 500 "$SEEN")
  printf '%s\n' "$keep" > "$SEEN"
}

main() {
  [[ -n $FIREWALL_ID ]] || die "set FWSYNC_FIREWALL_ID"
  local token; token=$(cat "$TOKEN_FILE") || die "cannot read token"

  local stmt msg sig ip ts nonce
  stmt=$(rendezvous_get) || die "rendezvous unreachable"
  msg=${stmt%%|*}; sig=${stmt#*|}
  [[ $msg != "$stmt" ]] || die "malformed statement"

  verify "$msg" "$sig" || die "signature does not verify - ignored"

  read -r ip ts nonce <<<"$msg"
  sane_ip "$ip" || die "implausible IP: $ip"
  local now; now=$(date +%s)
  (( now - ts <= MAX_AGE && ts - now <= MAX_AGE )) || die "stale statement (age $((now-ts))s)"

  # Replay guard: a nonce is single-use.
  touch "$SEEN"
  grep -qxF "$nonce" "$SEEN" && { echo "already applied"; exit 0; }

  # Read the current ruleset.
  local api="https://api.linode.com/v4/networking/firewalls/$FIREWALL_ID/rules"
  local rules; rules=$(curl -fsS -m 15 -H "Authorization: Bearer $token" "$api") || die "API read failed"

  # Rewrite every named rule's address to the new /32 and PUT it back. python3
  # does the JSON surgery so a stray sed cannot corrupt the ruleset, and it
  # reports whether anything actually needed changing - a substring grep for the
  # address would say "already there" when only one of the two rules had moved.
  local updated
  updated=$(RULE_LABELS="$RULE_LABELS" NEW_IP="$ip" python3 - "$rules" <<'PY'
import json, os, sys
r = json.loads(sys.argv[1])
want = os.environ["RULE_LABELS"].split()
ip = os.environ["NEW_IP"]
seen, changed = set(), False
for rule in r.get("inbound", []):
    if rule.get("label") in want:
        seen.add(rule["label"])
        addrs = rule.setdefault("addresses", {})
        if addrs.get("ipv4") != [f"{ip}/32"]:
            addrs["ipv4"] = [f"{ip}/32"]
            changed = True
missing = [l for l in want if l not in seen]
if missing:
    sys.exit("rule(s) not found: " + " ".join(missing))
print("CHANGED" if changed else "SAME")
print(json.dumps(r))
PY
) || die "$updated"

  local verdict=${updated%%$'\n'*}
  updated=${updated#*$'\n'}
  if [[ $verdict == SAME ]]; then
    spend "$nonce"; echo "firewall already at $ip/32 for: $RULE_LABELS"; exit 0
  fi

  curl -fsS -m 15 -X PUT -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
    -d "$updated" "$api" >/dev/null || die "API write failed"
  spend "$nonce"
  echo "firewall moved to $ip/32 for: $RULE_LABELS"
}

# Run only when executed, not when sourced, so the self-test can exercise the
# functions above without reaching for DuckDNS or the Linode API.
if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then main "$@"; fi
