# fw-autosync — keep the witness firewall pinned to a dynamic sensor IP

The witness's Linode firewall allows the sensor in by a tight `/32`. When the
sensor's ISP rotates its public IP (common on residential lines), that `/32`
goes stale and the sensor is locked out — SSH and the witness link both.

This keeps the `/32` **tight** and updates it automatically when the IP changes,
**without putting any cloud credential on the sensor** and without widening the
firewall.

## Why it does not leak

The naive fix — "let the witness see the sensor's IP when it connects and update
itself" — cannot work: the firewall drops the new-IP connection *before* the
witness sees it. So the sensor's new IP must travel over an **out-of-band**
channel, and that channel must be safe to read even if someone tampers with it.

- The sensor signs `{ip, timestamp, nonce}` with an **ed25519 key** whose public
  half the witness holds. It publishes the signed statement to a rendezvous
  (a DNS `TXT` record by default — anything both ends can reach outbound works).
- The witness fetches it, **verifies the signature**, rejects anything stale or
  replayed, and only then updates its own firewall to the proven IP.
- The **Linode API token lives only on the witness**, scoped to
  `firewalls:read_write` and nothing else. Compromise the sensor and there is no
  cloud token to steal, and no way to forge a signed IP without its private key.
- Even if the rendezvous is poisoned, the firewall is only ever moved to a
  cryptographically proven IP — and the real locks (the witness's **pinned
  mutual-TLS** and **key-only SSH**) are untouched regardless. The firewall is
  defence-in-depth, not the authentication.

Nothing here is secret in the repo: the private key, the token and the actual
addresses live on the two boxes, never in git.

## Layout

```
publish.sh   runs on the SENSOR: sign the current public IP, publish it
sync.sh      runs on the WITNESS: verify it, update the Linode firewall /32
```

## One-time setup

1. **Keypair** (dedicated to fw-autosync, not reused from anything):

   ```
   openssl genpkey -algorithm ed25519 -out fwsync.key       # -> sensor, chmod 600
   openssl pkey -in fwsync.key -pubout -out fwsync.pub       # -> witness
   ```

2. **Scoped token**, on the witness only: create a Linode Personal Access Token
   with **Firewalls: Read/Write** and no other scope. Store it root-only:

   ```
   sudo install -m 600 /dev/null /etc/mitmwatch/linode-fw.token
   sudo tee /etc/mitmwatch/linode-fw.token >/dev/null   # paste the token, Ctrl-D
   ```

3. **Firewall + rule id**: find them once and put them in `sync.sh`'s config
   (`FIREWALL_ID`, `RULE_LABEL`). `curl -H "Authorization: Bearer $T"
   https://api.linode.com/v4/networking/firewalls` lists them.

4. **Rendezvous**: implement `rendezvous_put` (sensor) and `rendezvous_get`
   (witness) for your provider. The default stubs use a Linode DNS `TXT` record
   via the Linode API — swap in your DNS host, an object store, or a gist. The
   signature is what makes the channel safe, so the store only has to be
   reachable, not trusted.

5. **Schedule**: a systemd timer on each box.

   ```
   # sensor: publish every 2 min (cheap; only writes when the IP changed)
   # witness: sync every 2 min
   [Unit]  Description=fw-autosync
   [Service] Type=oneshot ; ExecStart=/usr/local/bin/fw-%i.sh
   [Timer] OnBootSec=30 ; OnUnitActiveSec=120 ; [Install] WantedBy=timers.target
   ```

## Bootstrap

The updater cannot bring itself online through a firewall that is already
blocking the sensor — the very first stale-IP event still needs one manual
`tofu apply` (or a Linode Cloud Manager edit) to allow the current IP. After
that, rotations self-heal.
