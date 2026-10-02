# mitmwatch

Detects interception, redirection and tampering of network traffic, and says so
in language a non-technical person can act on.

One Go binary. Standard library first, `CGO_ENABLED=0` everywhere, so the same
source cross-compiles to a Raspberry Pi with no toolchain and no libpcap.

**Status: phase 2.** Nine probes across Windows, Linux and macOS, plus a remote
**witness** that corroborates the sensor's view from another network and ASN. On
Linux with raw-capture privileges (`setcap cap_net_raw`) it watches the wire;
elsewhere it falls back to the neighbour table and says so. `mitmwatch sensor`
runs it continuously with a LAN status page; `mitmwatch check` runs it once;
`mitmwatch witness` runs the outside vantage point. The per-host agent is phase 3
and not built yet — `doctor` lists exactly what is and is not covered rather than
letting a green screen imply otherwise.

Running today on a Raspberry Pi as a resident service, with a witness on another
continent corroborating its view over a pinned mutual-TLS link, and a status
page any device on the LAN can open.

## The dashboard

`mitmwatch sensor` serves a read-only status page on the LAN. It answers "is my
network okay right now?" in one glance and, when it is not, tells a
non-technical person what to do. Nothing loads from the internet — the page, its
styles and its icon are all served from the binary — so it renders even when the
internet is exactly what is broken. The browser-tab favicon turns red the moment
something needs attention, so a background tab still tells you.

The window is the frame. A rail down the left carries the six systems and the
sensor's own facts; the verdict runs across the top as the largest text on the
page; everything else fills what is left and scrolls inside itself, so the page
does not scroll and there is no dead band at the bottom of a large screen.
Nothing is centred and nothing has a maximum width.

It is laid out for the state it is in almost all of the time. In the calm state
there is no card chrome anywhere — the panes sit flush on the page ground,
separated by hairlines. The only rounded, filled, bordered object the design
owns is the alert card, so card chrome is the signal rather than decoration. An
alarm escalates on four channels that cost no layout at all: the verdict grows
and turns red, the top bar tints, a rule appears beneath it, and a frame is
drawn around the whole window. No track changes size, so nothing reflows under
the reader. There are no icons beyond one inline SVG mark, and no emoji.

*(The screenshots below use fabricated data; the attack shown is illustrative.)*

![mitmwatch dashboard showing a detected router-impersonation (ARP) attack — a red frame around the window, the verdict in large red type, the affected system floated to the top of the left rail, and an alert card carrying why, what to do and the evidence, above the device and activity panes](docs/dashboard.png)

It is responsive, and the same page reads cleanly on a phone:

<p align="center"><img src="docs/dashboard-mobile.png" width="380" alt="the mitmwatch dashboard on a phone: the rail unfolds into full-width sections in document order, and the device table drops its widest columns"></p>

When nothing is wrong it stays calm and green, with the device list and recent
activity to hand:

![mitmwatch dashboard in its all-clear state — a green verdict across the top, the six systems down the left rail with the sensor facts beneath them, and the device and activity panes filling the rest of the window](docs/dashboard-clear.png)

Devices are remembered by hardware address, so one that is switched off stays on
the list with the time it was last seen rather than silently disappearing, and
each row carries its own first-seen date. A device that rotates its address —
most phones do — is marked, because the history is then of the address and not
of the device.

The activity log is a record, not a scrollback. It is written to disk beside the
profile, survives restarts, is not erased by `baseline reset`, and each entry
keeps the evidence behind it. That matters most for an alert that has since
cleared: the card goes green and the alert disappears, and the entry is all
that is left. `/activity` shows the log in full, with what was seen and which
device it was:

![the mitmwatch activity page — each entry timestamped, naming the device, the severity and the check that fired, with the evidence behind it expandable](docs/activity.png)

Open it from any device on the network at `http://<sensor-ip>:8080` (set the
address with `dashboard` under `[sensor]` in the config).

The compact **Device audit** widget on the dashboard opens `/audit`, a separate
page with current findings and retained history filterable by device. It also
shows how long each inside probe and outside witness observation took. These
times measure detector observation duration, not end-to-end network latency; the
outside values appear when a configured witness reports them. Set `audit = false`
under `[sensor]` to disable the audit page, widget and local dashboard timing
collection. The default is on.

## Installing

Two parts, and the first one is useful on its own:

1. **The sensor** — watches your network. Runs on a Raspberry Pi, a spare Linux
   box, a Mac or a Windows machine.
2. **The witness** *(optional)* — a small server somewhere else in the world that
   looks at the same websites at the same moment, so its answers can be compared
   with yours. Costs about $5 a month.

Start with the sensor. Add the witness later if you want the extra check.

### What you need

| For | You need |
|---|---|
| Building | [Go](https://go.dev/dl/) 1.26 or newer. Nothing else — no C compiler, no libpcap, no system packages. |
| The sensor | Any always-on computer plugged into your network. A Raspberry Pi is ideal. It must be **wired**, not on Wi-Fi, to see everything. |
| The witness (optional) | A Linode account and about $5/month, or any small Linux server in a different country. |

The sensor sees the parts of your network that everyone shares — so a Pi plugged
into your router or a switch sees the whole house. Wi-Fi only shows that device's
own traffic, which is why wired matters.

### 1. Build it

```
git clone https://github.com/sizzlorox/mitmwatch
cd mitmwatch
go build -o mitmwatch ./cmd/mitmwatch
```

That produces one file called `mitmwatch`. There is nothing to install
alongside it.

Check what it can see on this machine:

```
./mitmwatch doctor
```

`doctor` prints what is covered here and what is not, and never changes
anything. Run it any time you want to know where you stand.

Then look at your network once:

```
./mitmwatch check
```

It exits `0` if everything looked fine and `1` if it found something, which is
what makes it usable from a cron job later.

**On the first run it will hold most findings back.** A brand-new install has no
idea what your network normally looks like, so it spends ten minutes learning
before it will raise anything but a critical finding. It lists what it held and
why. This is deliberate — a detector that cries wolf on day one is one you will
learn to ignore by day three.

### 2. Put it on the Raspberry Pi

From your development machine, with the Pi reachable over SSH:

```
make cross                          # builds for the Pi (linux/arm64)
make deploy PI_HOST=pi@raspberrypi.local
```

`make deploy` copies the binary, installs it to `/usr/local/bin/mitmwatch`, and
grants it the one permission it needs to read the network (`CAP_NET_RAW`). It
does not run as root.

Doing it by hand instead is three commands on the Pi:

```
sudo install -m 0755 mitmwatch /usr/local/bin/mitmwatch
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/mitmwatch
sudo mkdir -p /etc/mitmwatch /var/lib/mitmwatch
```

If `setcap` is "not found", it lives in `/sbin` and your shell may not look
there — use `/sbin/setcap`.

### 3. Configure it

Copy the example config to the place the sensor looks for it:

```
sudo cp mitmwatch.example.toml /etc/mitmwatch/mitmwatch.toml
sudo nano /etc/mitmwatch/mitmwatch.toml
```

Every setting has a default that works, so you only need to change two things to
start:

```toml
[sensor]
role      = "always-on"      # "roaming" for a laptop that sleeps
dashboard = ":8080"          # turns on the status page

[alerts]
sinks = ["log", "ntfy"]
ntfy_topic = "https://ntfy.sh/pick-something-nobody-can-guess"
```

**About that topic name.** [ntfy](https://ntfy.sh) is how the sensor reaches your
phone. It needs no account and no signup: you invent a name, install the ntfy
app, and subscribe to that name. Anyone who guesses the name can read your
alerts, so pick something long and unguessable — not `home` or `mitmwatch`.

Without a push sink the sensor still records everything, but nothing will tell
you. That matters most at 3am, which is the point of the whole exercise.

Other files live at:

| | |
|---|---|
| Config, when running as root | `/etc/mitmwatch/mitmwatch.toml` |
| Config, as a normal user | your user config directory — `mitmwatch doctor` prints the exact path |
| Learned baselines and history | `/var/lib/mitmwatch/` as root, per-user otherwise |

Worth knowing, because it surprises people: **`mitmwatch check` and
`sudo mitmwatch check` read different config files and different baselines.**
The service runs as root, so when you are checking on the service, use `sudo`.
`doctor` always prints which files it actually used.

### 4. Run it for good

Install the service unit that ships in `docs/`:

```
sudo cp docs/mitmwatch-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mitmwatch-sensor
```

Check it came up:

```
systemctl status mitmwatch-sensor
journalctl -u mitmwatch-sensor -f      # watch it work; Ctrl-C to stop watching
```

Then open the dashboard from any device on your network:

```
http://<the-pi's-address>:8080
```

It should say **All clear**, or tell you it is still learning. That is the whole
setup for the sensor.

### 5. The witness, if you want it (optional)

Everything above works without this. The witness adds one thing the sensor can
never do alone: a second opinion from outside your network. If someone between
you and the internet is swapping certificates, your sensor and a machine on
another continent will not see the same thing — and that disagreement is very
hard for an attacker to arrange.

It has to be somewhere **else**. A server sharing your internet connection
corroborates whatever your connection is already doing, which is worth nothing.

**Create the server.** There is a recipe in `infra/` that builds and hardens it
for you using [OpenTofu](https://opentofu.org/):

```
ssh-keygen -t ed25519          # skip if you already have a key
cp infra/.env.example infra/.env
nano infra/.env                # paste a Linode API token; the file is gitignored
infra/tofu.sh init
infra/tofu.sh apply
```

You will need a Linode API token with **Linodes: Read/Write** and **Firewalls:
Read/Write**, made at cloud.linode.com under API Tokens. It does not need
anything else.

The SSH key matters: the server is built with password login disabled, so
without a key there is no way in except Linode's browser console.

Prefer to use a server you already have? Anything running Debian works. Copy the
binary to it and skip to the pairing step.

**Install the same binary there:**

```
make cross-amd64
make deploy-witness WITNESS_HOST=user@your-server
```

**Introduce the two machines.** They authenticate each other by key — no
passwords, no certificate authority, so there is nothing to mis-issue. The
introduction goes in this order, because each side has to learn the other's key
before it will talk at all.

*On the sensor,* ask for its own key:

```
sudo mitmwatch witness pair --addr your-server:8443
```

It prints `this sensor's pin: sha256/...` and then fails to connect, because
nothing is listening on the witness yet. That is expected — you ran it for the
pin. Copy that line.

*On the witness,* create its config and register the sensor's key:

```
sudo mkdir -p /etc/mitmwatch /var/lib/mitmwatch
sudo mitmwatch witness allow sha256/<the-sensor-pin-you-copied>
```

Like `pair`, `allow` **prints** a block rather than editing anything. Write the
config out with what it printed:

```toml
[witness]
listen     = ":8443"
allow_pins = [
  "sha256/...",          # exactly what `witness allow` printed
]
```

The witness refuses to start with an empty `allow_pins` — a witness that accepts
anyone is not a witness. Now start it:

```
sudo cp docs/mitmwatch-witness.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mitmwatch-witness
```

**Let the sensor in.** The witness's firewall starts closed. Put the addresses
your home connection uses into `infra/.env` and apply:

```
TF_VAR_witness_port_open=true
TF_VAR_witness_allow_cidrs=["203.0.113.0/24"]
```

```
infra/tofu.sh apply
```

To find the right value, run this on the sensor and use the `inetnum` range it
prints:

```
whois "$(curl -s https://api.ipify.org)" | grep -iE '^(inetnum|netname)'
```

Use the whole range, not your single current address. Home connections get a new
address every so often, and a rule pinned to one address locks the sensor out of
its own witness the moment that happens — quietly, while everything else keeps
working. Keep real values in `infra/.env`; it is gitignored so they never reach
a public repository.

**Finish the introduction.** Back on the sensor, run `pair` again. This time the
witness is listening and reachable, so it completes:

```
sudo mitmwatch witness pair --addr your-server:8443
```

It verifies the link and prints a `[witness]` block. Paste that into the
sensor's `/etc/mitmwatch/mitmwatch.toml`:

```toml
[witness]
sync = true
addr = "your-server:8443"
pin  = "sha256/..."          # exactly what `witness pair` printed
```

Restart the sensor so it picks it up:

```
sudo systemctl restart mitmwatch-sensor
```

**Confirm it worked.** The dashboard's left rail should read
`outside — connected`. Or ask directly:

```
mitmwatch witness status
```

### Checking it actually works

```
mitmwatch doctor            # what is covered here, and what is not
mitmwatch check             # look once, now
mitmwatch baseline show     # what it has learned about this network
mitmwatch profiles list     # every network it has seen
```

If something fires and you know it was you — a work laptop's corporate
certificate, a second router you added — tell it so and it stops asking:

```
mitmwatch baseline accept <hash>          # the hash is printed with the finding
mitmwatch profiles trust <key> work       # a managed laptop's private CA is expected here
```

### When something is wrong

| Symptom | Cause |
|---|---|
| `doctor` says capture is "device tables" instead of "the wire" | The capability is missing. Re-run `sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/mitmwatch`. |
| Dashboard will not open from another device | `dashboard` is set to `127.0.0.1:8080`, which is this machine only. Use `:8080`. |
| Everything is "held back while learning" | Normal for the first ten minutes on a network it has not seen. |
| `journalctl` prints nothing at all | Your user is not in the `adm` group. `sudo journalctl -u mitmwatch-sensor`. |
| The dashboard says the outside check is down | Usually the witness firewall no longer covers your address — see the range advice above. |
| It sees very few devices | The sensor is on Wi-Fi, or on a switch port that does not carry other devices' traffic. Wire it to the router. |

## Day to day

```
mitmwatch check tls truststore        # just these probes
mitmwatch baseline show               # what has been learned
mitmwatch baseline accept <hash>      # "this was me"
mitmwatch profiles list
mitmwatch profiles trust <key> work   # a managed laptop's private CA is expected
```

## The idea

Two ideas carry most of the detection, and both are cheap.

**Listen, then compare.** The `arp` probe reads both the host's neighbour table and the wire itself. The table holds one winner per address; the wire holds the argument. Two devices claiming one address in a five-second window is that argument in progress, and it is very hard to arrange by accident.

**Verify every chain twice.** Once against a Mozilla root bundle embedded in
the binary, once against the trust store of the machine it is running on. A
detector that consults only the system store cannot see a root injected *into*
that store — which is exactly how ESET, mitmproxy, Burp and corporate proxies
work. The disagreement between the two verdicts is the finding.

**Watch the trust store directly.** Real interceptors filter selectively. On
the machine this was written on, ESET's SSL filter rewrites certificates for
.NET and browser processes and leaves an unrecognised binary alone — so the
canary probes see a clean network while the browser is being read. No capture
tier, vantage point or witness can close that gap; the interception never
touches the sensor's traffic. Enumerating the trust store can, because the
injected root has to be there for the attack to work at all.

## An outside opinion

Some interception is invisible from inside the network: if your resolver and your
route are both controlled, one host cannot tell a redirected site from the real
one. A **witness** on a different network and ASN — a small VPS on another
continent — gives a second vantage point. It drives the exchange (the witness
issues the tick; the sensor never trusts a shared clock), the two ends
authenticate by pinned SPKI over mutual TLS 1.3 with no certificate authority in
the path, and the comparison is built to be *vantage-independent*: an honest
certificate that merely serves from a different CDN edge or geo-route does not
produce a finding, while one never published to a public log, or a chain that
reaches a different root, does. The witness also runs a dead-man's switch —
silencing the sensor is itself a signal the sensor cannot suppress.

Cross-vantage DNS and issuer comparison from a *single* witness is deliberately
not an alarm on its own: CDNs legitimately resolve to different addresses, and
occasionally different CAs, by region, and one outside vantage cannot tell that
apart from an attack. That needs several witnesses in agreement — future work.

## What it looks for today

| Probe | Catches |
|---|---|
| `nameres` | A device answering LLMNR/NBT-NS/mDNS for names that are not its own - the signature of Responder and similar credential-theft tools. The evidence separates names somebody asked for from names that were merely announced, because a tool answers questions |
| `dhcp` | A device offering a gateway, resolver, or proxy configuration that is not this network's - a man-in-the-middle that forges nothing |
| `arp` | Something else answering for your router - the classic same-segment attack. From the wire: two devices claiming one address, live. From the neighbour table: a gateway whose hardware changed, or one device holding both the router's address and its own |
| `nd` | A new device advertising itself as your IPv6 router, or an existing one changing the DNS server it hands out - the SLAAC man-in-the-middle, which needs no ARP because hosts prefer IPv6 |
| `truststore` | A certificate authority added to this machine, or a recently created one that browsers do not ship with |
| `tls` | A chain trusted only locally; one key serving companies that do not share one; certificates never published to a public log; a certificate from an authority the site's own DNS (CAA) does not permit; protocol downgrade |
| `dns` | The local resolver sending a name somewhere different from an independent lookup, or inventing an address for a name that does not exist |
| `sslstrip` | A site that promises https answering in the clear, or one that stopped promising |
| `clock` | System time far enough out to make an expired certificate look valid |

Findings carry a score; scores add up per target; bands decide whether anyone
is interrupted (info < 20, low 20, medium 40, high 60, critical 80). Every
weight is in the config file, because they are guesses until the lab and soak
phases say otherwise.

One deliberate exclusion, and the reasoning for it, since a detector that
quietly ignores things is not one. Every browser publishes a random
`<uuid>.local` name over mDNS for each address it can be reached on, once per
connection a web page opens — RFC 8828, so that a site cannot learn the
machine's address on your network. A desktop with tabs open publishes a handful,
discards them and publishes a fresh set, which to a rule that counts names looks
exactly like a host claiming to be five things at once. Measured on a live home
network: two machines produced 26 of these in fifteen minutes, and every genuine
service name on the same wire was being queried by somebody while not one of the
26 ever was.

`nameres` therefore does not count a name that is a canonical UUID, ends in
`.local`, arrived over mDNS, **and** was asked for by nobody. All four, because
each one is a way for a real claim to be mistaken for a placeholder. This does
not blind the rule: name poisoning works by answering the question a victim
asked — `wpad`, a file server, a NetBIOS name — so that the victim connects and
authenticates, and nothing ever asks for a random UUID it was not already given
out of band. When the exclusion changes an outcome it is reported as an
info-band finding rather than left to be inferred from silence, and
`ignore_browser_candidates = false` under `[nameres]` turns it off.

## What it does not do

- **Passive eavesdropping.** A silent tap leaves no trace. Out of scope by design, not by omission.
- **Anything that happens between listen windows.** Capture samples for a few seconds per pass rather than running continuously. That is enough for ARP poisoning, which repeats about once a second because it has to; it is not enough for a one-off event. A resident sensor daemon is what closes it.
- **Wi-Fi monitor mode.** Evil-twin access points and deauth floods live below the ethernet frame and need a radio in monitor mode, which a wired sensor cannot provide. Phase 4 - `doctor` says so.
- **Other machines on the network.** The per-host agent, which catches an injected root or forced proxy on a laptop the sensor cannot see the traffic of, is phase 3.
- **Blocking anything.** This is a tripwire, not a firewall.

## Design notes worth knowing

**Two Cloudflare-fronted hosts sharing one certificate is normal.** So shared
key material is only a finding when it spans hosts whose issuers are different
organisations, or when the shared chain does not reach a public root at all.
The naive rule would fire on the default configuration.

**Bare "not in Mozilla's bundle" is useless as an alarm.** Measured on a clean
Windows 11 install: 68 distinct roots, 38 absent from Mozilla's, 27 of those
able to vouch for a website. Adding "created within the last 400 days" cuts it
to exactly the roots a human or an application installed locally.

**A private root on a managed work laptop is expected, once.** Set the profile
to `work` and a stable private CA drops to informational — but one that newly
appears keeps full weight. Without that, the laptop deployment is permanently
critical and the user stops looking.

**The detector must not learn its own attacker.** A probe whose worst single
finding reaches high keeps its previous baseline, so an interceptor never
becomes the new normal. Issuer learning stays off until a witness can seed it
from outside.

**Nothing is fetched at runtime that could be tampered with silently.** The
DNS-over-HTTPS comparison channel is verified against the embedded bundle only.
If that makes it unreachable, that is reported as a finding rather than quietly
downgraded to a weaker check.

## Refreshing the embedded roots

```
make roots      # downloads, verifies the digest, replaces, re-runs the tests
```

The published digest travels over the same connection as the bundle, so this
check is worth less than it looks when run from a host that is itself
intercepted. `doctor` prints the digest; compare it against
`curl.se/ca/cacert.pem.sha256` from a machine you know is clean.

## Layout

```
cmd/mitmwatch      CLI: check, doctor, baseline, profiles, sensor, witness
internal/roots     embedded Mozilla bundle - the trust anchor for everything else
internal/probe     Probe interface, registry, and one package per detector
internal/capture   frame source; tier selection (tier 2 and 1 in phase 1 and 3)
internal/frame     hand-written, bounds-checked wire parsers (eth/arp/ip/udp/dhcp/ra)
internal/witness   cross-vantage protocol: pinned mutual TLS, witness-driven ticks
internal/osq       per-OS network queries
internal/core      baseline profiles, verdict scoring, alert sinks
internal/web       the read-only LAN status page
internal/config    TOML config and the weights table
```

Adding a detector is one package with an `init()` that calls `probe.Register`.
Probes never alert; they emit findings, and `core/verdict` decides what that
means.

## Tests

```
go test ./...
```

Every `Compare` has fixture-pair tests, including the false positives that were
found the hard way: the shared CDN certificate, and the host that never
advertised HSTS in the first place.

## License and contributing

mitmwatch is licensed under the [Apache License 2.0](LICENSE).

Before contributing, read **[AGENTS.md](AGENTS.md)**. It is written for AI coding
agents and humans alike: it covers the architecture and conventions, and it
defines the security invariants a change must not weaken — a detector whose
integrity can be quietly eroded is worse than none. To report a vulnerability,
see [SECURITY.md](SECURITY.md).
