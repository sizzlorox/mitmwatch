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
publish.sh   runs on the SENSOR:  sign the current public IP, publish it
sync.sh      runs on the WITNESS: verify it, update the Linode firewall /32
selftest.sh  runs anywhere:       the whole round trip, offline
*.service/*.timer                 systemd units for both sides
```

## The rendezvous is DuckDNS

The statement travels in a **TXT record on a free DuckDNS hostname**. The sensor
writes it; the witness reads it with one `dig`.

DuckDNS was chosen over a real DNS provider for one reason: the credential. A
Cloudflare token can edit a zone, a Linode token can edit every domain on the
account. A DuckDNS token updates exactly one hostname and can do nothing else —
and since the entire premise is that stealing the sensor must not hand anyone a
way to move the witness's firewall, the narrowest credential wins. This one is
narrow enough to be uninteresting.

The channel is still not trusted. DuckDNS could serve anything and the witness
would reject it, because only the ed25519 signature is believed. What DuckDNS
*can* do is withhold or replay a statement — denial of service, not
redirection — and a withheld statement fails closed, leaving the firewall where
it is. Only the TXT record is read; the A record on the same name is ignored on
purpose, because acting on an unauthenticated lookup is the one mistake that
would undo all of this.

Run `./selftest.sh` to see it: 29 checks covering the signature, a statement
signed by the wrong key, TXT quoting and chunk-splitting, staleness in both
directions, the replay guard, and the firewall rewrite itself — including that
an unrelated rule is left alone and that a missing label fails loudly rather
than quietly doing nothing. It touches neither DuckDNS nor Linode.

### Why the sensor republishes on a timer, not only on change

A statement expires — `sync.sh` refuses anything older than `MAX_AGE` (600s).
If the sensor published only when its address moved, a witness that was down,
rebooting or simply not polling during that one window would never see a valid
statement again, and the firewall would stay pinned to an address that no longer
exists.

That is not hypothetical. It is exactly how this deployment locked itself out:
the address rotated at 04:32, and by the time anyone looked the only statement
that had ever been published was long expired. `publish.sh` now republishes
whenever the last statement is older than `FWSYNC_REFRESH` (180s), whether or
not anything changed.

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

3. **Firewall and rule labels**: find them once. `curl -H "Authorization: Bearer $T"
   https://api.linode.com/v4/networking/firewalls` lists the firewall and its id;
   `.../firewalls/<id>/rules` lists the inbound rules and their labels.

   List **every** rule pinned to the sensor's address, not just the witness
   port. This deployment has two, `ssh` and `witness-mtls`, and moving only one
   is its own lockout: the witness link comes back while SSH stays pinned to an
   address that no longer exists.

4. **DuckDNS**: sign in at [duckdns.org](https://www.duckdns.org) (it wants
   nothing but an OAuth login), create one subdomain, and copy the token. On the
   **sensor** only:

   ```
   sudo install -m 600 /dev/null /etc/mitmwatch/duckdns.token
   sudo tee /etc/mitmwatch/duckdns.token >/dev/null      # paste the token, Ctrl-D
   ```

   The token is worth nothing to an attacker: it moves one DNS record that the
   witness does not trust anyway.

5. **Environment**, `/etc/mitmwatch/fwsync.env` on both boxes — the units read
   it. Use the same subdomain on each:

   ```
   # sensor
   FWSYNC_DUCKDNS_DOMAIN=your-subdomain

   # witness
   FWSYNC_DUCKDNS_DOMAIN=your-subdomain
   FWSYNC_FIREWALL_ID=1234567          # from step 3
   FWSYNC_RULE_LABELS="ssh witness-mtls"   # every rule pinned to the sensor
   ```

6. **Install and schedule**:

   ```
   # sensor
   sudo install -m 755 publish.sh /usr/local/bin/fwsync-publish
   sudo install -m 644 mitmwatch-fwsync-publish.{service,timer} /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now mitmwatch-fwsync-publish.timer

   # witness
   sudo install -m 755 sync.sh /usr/local/bin/fwsync-sync
   sudo install -m 644 mitmwatch-fwsync-sync.{service,timer} /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now mitmwatch-fwsync-sync.timer
   ```

   Check either side with `systemctl status mitmwatch-fwsync-*.service` or
   `journalctl -u mitmwatch-fwsync-sync`. The witness logs `firewall already at
   <ip>/32` on a quiet tick and `firewall moved to <ip>/32` when it acts.

   The witness's `dig` comes from `dnsutils` (`bind-utils` on RPM); install it
   if `rendezvous_get` reports the rendezvous unreachable on an otherwise
   healthy box.

## Bootstrap

The updater cannot bring itself online through a firewall that is already
blocking the sensor — the very first stale-IP event still needs one manual
`tofu apply` (or a Linode Cloud Manager edit) to allow the current IP. After
that, rotations self-heal.
