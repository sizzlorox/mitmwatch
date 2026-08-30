#!/usr/bin/env bash
# publish.sh - SENSOR side of fw-autosync.
#
# Learn this box's current public IP, sign {ip, timestamp, nonce} with the
# fw-autosync ed25519 key, and publish the signed statement to the rendezvous.
# Runs on a short timer; it only republishes when the IP actually changed, so it
# is cheap to run every couple of minutes.
#
# It holds NO cloud/infra credential - only its signing key and whatever narrow,
# single-record credential the rendezvous needs. Neither can touch the witness
# or its firewall; the witness trusts the *signature*, not the channel.
set -euo pipefail

KEY="${FWSYNC_KEY:-/etc/mitmwatch/fwsync.key}"   # ed25519 private key, chmod 600
STATE="${FWSYNC_STATE:-/var/lib/mitmwatch/fwsync.last}"

# REFRESH is why this is not only a change detector.
#
# A statement expires: the witness rejects anything older than its MAX_AGE, 600s
# by default. If the sensor published only when its address changed, a witness
# that was down, rebooting, or simply not polling during that one window would
# never see a valid statement again, and the firewall would stay pinned to an
# address that no longer exists. That is not hypothetical - it is how this
# deployment locked itself out.
#
# So republish on a cadence well inside the witness's expiry, whether or not
# anything changed. A DNS update every few minutes costs nothing.
REFRESH="${FWSYNC_REFRESH:-180}"

# --- rendezvous: DuckDNS ----------------------------------------------------
# The statement travels in a TXT record on a free DuckDNS hostname.
#
# DuckDNS over a real DNS provider, for one reason: the credential. A Cloudflare
# or Linode token can edit records across a zone or an account. A DuckDNS token
# updates exactly one hostname and can do nothing else. The whole point is that
# stealing the sensor must not hand anyone a way to move the witness firewall,
# so the narrowest possible credential is the right one, and this one is narrow
# enough to be uninteresting.
#
# The channel is still not trusted - only the ed25519 signature is. DuckDNS
# could serve anything and the witness would reject it. What DuckDNS can do is
# withhold or replay, which is denial of service rather than redirection, and a
# withheld statement fails closed: the firewall stays where it was.
#
# Only the TXT record is used. DuckDNS also keeps an A record and it is
# deliberately ignored - the witness must act on an address it can verify a
# signature over, never on an unauthenticated lookup.
DUCK_DOMAIN="${FWSYNC_DUCKDNS_DOMAIN:-}"                            # label only, no .duckdns.org
DUCK_TOKEN_FILE="${FWSYNC_DUCKDNS_TOKEN:-/etc/mitmwatch/duckdns.token}"

rendezvous_put() {
  # $1 = the signed statement (one line). Publish it verbatim.
  [[ -n $DUCK_DOMAIN ]] || { echo "set FWSYNC_DUCKDNS_DOMAIN" >&2; return 1; }
  local token; token=$(cat "$DUCK_TOKEN_FILE") || { echo "cannot read $DUCK_TOKEN_FILE" >&2; return 1; }

  # --data-urlencode, not interpolation: the signature is base64 and carries +,
  # / and =, each of which means something else in a query string. -G puts the
  # encoded pairs back onto the URL as a GET.
  local out
  out=$(curl -fsS -m 15 -G \
          --data-urlencode "domains=$DUCK_DOMAIN" \
          --data-urlencode "token=$token" \
          --data-urlencode "txt=$1" \
          https://www.duckdns.org/update) || { echo "duckdns unreachable" >&2; return 1; }

  # DuckDNS answers "OK" or "KO" in the body and returns 200 either way, so
  # curl's exit status says nothing about whether the record was written.
  [[ $out == OK* ]] || { echo "duckdns refused the update: $out" >&2; return 1; }
  return 0
}

# --- current public IP ------------------------------------------------------
public_ip() {
  local ip
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    ip=$(curl -fsS -m 8 "$u" 2>/dev/null | tr -d '[:space:]') || continue
    # accept only a bare IPv4
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { echo "$ip"; return 0; }
  done
  return 1
}

main() {
  local ip; ip=$(public_ip) || { echo "could not determine public IP" >&2; exit 1; }

  # Publish when the address changed, or when the last statement is old enough
  # that the witness would refuse it. See REFRESH above for why the second
  # condition is not optional.
  if [[ -f $STATE ]]; then
    local last_ip last_at
    read -r last_ip last_at < "$STATE" || true
    if [[ ${last_ip:-} == "$ip" ]] && (( $(date +%s) - ${last_at:-0} < REFRESH )); then
      exit 0
    fi
  fi

  local ts nonce msg sig stmt
  ts=$(date +%s)
  nonce=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  msg="$ip $ts $nonce"

  # ed25519 raw signature over the exact message bytes (OpenSSL 3+). Ed25519 is
  # one-shot, so the message must come from a file, not a stdin pipe.
  local mf; mf=$(mktemp); printf '%s' "$msg" > "$mf"
  sig=$(openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$mf" 2>/dev/null | base64 -w0)
  rm -f "$mf"
  [[ -n $sig ]] || { echo "signing failed" >&2; exit 1; }
  stmt="$msg|$sig"

  # State is written only after the publish succeeded, so a failed update is
  # retried on the next tick rather than recorded as done.
  rendezvous_put "$stmt"
  printf '%s %s\n' "$ip" "$ts" > "$STATE"
  echo "published $ip @ $ts"
}

# Run only when executed, not when sourced, so the self-test can exercise the
# functions above without reaching for DuckDNS or the Linode API.
if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then main "$@"; fi
