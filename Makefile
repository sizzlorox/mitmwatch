# mitmwatch

GO      ?= go
BIN     ?= mitmwatch
# Deploy targets go through sudo (neither a Pi nor a hardened VPS allows root
# login). Set these to your own hosts - either on the command line
# (`make deploy PI_HOST=you@pi`) or, to keep them out of git, in a local
# `Makefile.local` (git-ignored) that overrides them.
PI_HOST      ?= pi@raspberrypi.local
WITNESS_HOST ?= witness@example.net

# Optional local overrides (host addresses, private tweaks); never committed.
-include Makefile.local

.PHONY: build test vet race check-all roots cross cross-amd64 deploy deploy-witness soak clean

build:
	CGO_ENABLED=0 $(GO) build -o $(BIN) ./cmd/mitmwatch

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...
	GOOS=linux   $(GO) vet ./...
	GOOS=darwin  $(GO) vet ./...
	GOOS=windows $(GO) vet ./...

# The race detector needs cgo, and the development box has no C compiler. The
# witness does, so the suite is shipped there and run under -race remotely.
# Concurrency in a security tool is not something to take on trust: pass() runs
# every probe together and the capture fan-out feeds them all from one socket.
race:
	@tar czf /tmp/mitmwatch-src.tgz --exclude=.git --exclude='*.exe' --exclude='$(BIN)-linux-*' 		--exclude=infra/.terraform --exclude='infra/terraform.tfstate*' --exclude=infra/.env .
	@scp -q /tmp/mitmwatch-src.tgz $(WITNESS_HOST):/tmp/
	@ssh $(WITNESS_HOST) 'set -e; rm -rf /tmp/mw && mkdir -p /tmp/mw && 		tar xzf /tmp/mitmwatch-src.tgz -C /tmp/mw && rm -f /tmp/mitmwatch-src.tgz && 		cd /tmp/mw && PATH=/usr/local/go/bin:$$PATH CGO_ENABLED=1 go test -race ./... 2>&1 | grep -v "no test files"'

check-all: vet test race

# Refresh the embedded Mozilla bundle. The digest is verified before the file
# is replaced; see README on why that check is weaker than it looks when run
# from an intercepted host.
roots:
	curl -fsS -o internal/roots/cacert.pem.new https://curl.se/ca/cacert.pem
	curl -fsS -o internal/roots/cacert.pem.sha256 https://curl.se/ca/cacert.pem.sha256
	cd internal/roots && sha256sum -c --ignore-missing --status <(sed "s/cacert.pem/cacert.pem.new/" cacert.pem.sha256)
	mv internal/roots/cacert.pem.new internal/roots/cacert.pem
	$(GO) test ./internal/roots/

# The Raspberry Pi target. No cgo, no cross toolchain, no libpcap.
cross:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -o $(BIN)-linux-arm64 ./cmd/mitmwatch

cross-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BIN)-linux-amd64 ./cmd/mitmwatch

# The Pi: the sensor. setcap is what lets phase 1 open a raw socket without
# running the whole daemon as root. /sbin is not on a non-root PATH on Debian,
# hence the absolute path - `command -v setcap` lies here.
deploy: cross
	scp $(BIN)-linux-arm64 $(PI_HOST):/tmp/$(BIN)
	ssh $(PI_HOST) "sudo install -m 0755 /tmp/$(BIN) /usr/local/bin/$(BIN) && sudo /sbin/setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/$(BIN) && rm -f /tmp/$(BIN)"
	ssh $(PI_HOST) "sudo $(BIN) doctor | head -20"

# The witness: the outside opinion. No raw capture there, so no setcap.
deploy-witness: cross-amd64
	scp $(BIN)-linux-amd64 $(WITNESS_HOST):/tmp/$(BIN)
	ssh $(WITNESS_HOST) "sudo install -m 0755 /tmp/$(BIN) /usr/local/bin/$(BIN) && rm -f /tmp/$(BIN)"

# What the soak has actually produced, on both boxes.
soak:
	@echo "--- pi ($(PI_HOST)) ---"
	@ssh $(PI_HOST) "journalctl -u mitmwatch-check.service --since -24h --no-pager | grep -cE 'all clear' | xargs -I{} echo 'clean passes: {}'; journalctl -u mitmwatch-check.service --since -24h --no-pager | grep -E '^\[' || true"
	@echo "--- witness ($(WITNESS_HOST)) ---"
	@ssh $(WITNESS_HOST) "journalctl -u mitmwatch-check.service --since -24h --no-pager | grep -cE 'all clear' | xargs -I{} echo 'clean passes: {}'; journalctl -u mitmwatch-check.service --since -24h --no-pager | grep -E '^\[' || true"

clean:
	rm -f $(BIN) $(BIN).exe $(BIN)-linux-arm64 $(BIN)-linux-amd64
