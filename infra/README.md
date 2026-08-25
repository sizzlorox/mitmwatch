# infra

One Linode, two jobs.

Today it is the **Linux target the project does not otherwise have**. `internal/osq/osq_linux.go`
and `internal/probe/truststore/store_unix.go` had never executed anywhere, and phase 0 cannot
exit until a clean network produces zero findings somewhere that is not the intercepted
development machine.

From phase 2 it becomes the **witness**: an independent vantage point on a different country and
ASN, running the same probes against the same targets at the same moment, so that "the sensor
sees X" can be checked against "someone outside sees Y".

## Use

```
LINODE_ENV_FILE=/path/to/other/project/.env infra/tofu.sh plan
LINODE_ENV_FILE=...                          infra/tofu.sh apply
```

`tofu.sh` reads `infra/.env` for this deployment's settings, and takes only the credential from
`LINODE_ENV_FILE`. A foreign project's file must not contribute its `TF_VAR_region` — that is an
answer to a different question, and letting it through deploys this box wherever that one lives.

`infra/.env` is gitignored. It holds `TF_VAR_ssh_allow_cidrs`, because an operator's home address
does not belong in a committed file and rots if it is.

cloud-init runs once, at first boot, and `metadata` is in `ignore_changes`. To adopt a change to
`cloud-init/witness.yaml` you must rebuild deliberately:

```
infra/tofu.sh apply -replace=linode_instance.witness    # new IP
```

## Security posture

The governing constraint is that **a witness that is itself modified is worse than no witness**,
because it corroborates falsely. So the hardening is all subtraction. Nothing on this host
installs a certificate authority, a TLS proxy, or an inspection agent, and nothing should.

| Control | Where |
|---|---|
| Inbound default DROP; only SSH open, restricted to one CIDR | `main.tf` firewall |
| No IPv6 SSH rule — sshd listens on v6, so omitting it is what keeps the v6 internet out of a port the v4 rule narrowed | `main.tf` |
| Phase 2 witness port stays closed until something listens on it | `witness_port_open` |
| Root SSH disabled; `ops` + passwordless sudo, key only | cloud-init |
| `AuthenticationMethods publickey`, `MaxAuthTries 3`, `LoginGraceTime 20` | cloud-init |
| No TCP/agent/stream/tunnel/X11 forwarding — a vantage point must never become a pivot | cloud-init |
| fail2ban on the systemd journal, with the operator CIDR in `ignoreip` | cloud-init |
| Unattended security upgrades, no automatic reboot | cloud-init |
| sysctl: ICMP redirects off, source routing off, rp_filter, syncookies, no forwarding | cloud-init |
| `mitmwatch check` service runs `ProtectSystem=strict`, `NoNewPrivileges` | cloud-init |

Outbound is deliberately `ACCEPT`. This host's job is to reach arbitrary internet hosts and
report how they look from here; an egress allowlist would need widening for every target added
to the config, and a stale one would turn a probe failure into a false finding. The exposure
that matters on a witness is inbound.

`ignoreip` matters more than it looks: SSH is restricted to a single CIDR, so fail2ban banning
that CIDR would lock the operator out entirely. It is templated from the same variable that
writes the firewall rule.

**But that binding only holds at build time.** cloud-init runs once, so changing
`TF_VAR_ssh_allow_cidrs` updates the firewall on the next `apply` and leaves `ignoreip` behind
until the box is rebuilt. Widening the firewall without rebuilding therefore admits addresses
fail2ban is still willing to ban. Either rebuild after changing it, or edit
`/etc/fail2ban/jail.d/sshd.local` to match. This bit us the first time the CIDR was widened.

The CIDR is the ISP pool, not a single address, because it guards a *dynamic* residential
connection: a `/32` stops answering the moment the address rotates, and an unreachable box is
a soak whose results nobody can collect. SSH is key-only, root is disabled and fail2ban is
behind it, so the source restriction is defence in depth rather than the primary control.
Narrow it to a `/32` if the address is static.

## If SSH stops answering

That is the firewall doing its job after a dynamic address changed. Neither recovery path needs
SSH:

- the **Lish console** in the Linode manager, or
- update `TF_VAR_ssh_allow_cidrs` in `infra/.env` and re-apply **from anywhere** — tofu talks to
  the Linode API, not to this box.

## Platform gotchas, all found the hard way

- **grub-pc cannot be configured on Linode.** The instance gets a raw filesystem with no
  partition table, so `grub-install` has nowhere to embed and fails with `blocklists are
  invalid`. `package_upgrade` then trips it, dpkg exits 1, apt exits 100, and cloud-init reports
  the entire boot failed although every package installed. Preseeding does not fix it: a
  `debconf-set-selections` line will not clear the non-empty `install_devices` the image ships,
  and a `debconf-communicate SET` is overwritten when grub-pc's config script re-detects the
  disk during the upgrade. The packages are held instead. Boot is unaffected; Linode does not
  boot this disk's MBR.
- **fail2ban's default backend finds no log.** Bookworm logs authentication to the journal and
  ships no `/var/log/auth.log`, so the sshd jail refuses to start and takes the whole service
  down: `Have not found any log file for sshd jail`. `backend = systemd`.
- **One bad package name kills the entire boot.** cloud-init runs a single `apt-get` for the
  whole list, and the package module runs before `runcmd`, so everything after it is skipped.
  `ntpsec-ntpdate` does not exist on bookworm and cost a full provisioning run. Verify every
  name against the target release before adding it.
- **`sysctl` is not on a non-root PATH** on Debian. `/usr/sbin/sysctl -n` when checking by hand,
  or you will read blank values and think the hardening did not apply.
