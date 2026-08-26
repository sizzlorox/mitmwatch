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

# --- rendezvous (pluggable) -------------------------------------------------
# Replace with your provider. The default is a placeholder that MUST be
# implemented; the signature is what keeps the channel safe, so the store only
# has to be reachable, not trusted. Example: update a DNS TXT record you own.
rendezvous_put() {
  # $1 = the signed statement (one line). Publish it verbatim.
  echo "rendezvous_put not implemented - see README" >&2
  return 1
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

  # Only publish on change - the timer runs often, the IP rarely moves.
  if [[ -f $STATE && $(cat "$STATE") == "$ip" ]]; then
    exit 0
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

  rendezvous_put "$stmt"
  echo "$ip" > "$STATE"
  echo "published $ip @ $ts"
}
main "$@"
