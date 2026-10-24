# Wisp EDR -- top-level build.
#
#   make              build the sensor (eBPF) and the console
#   make test         unit tests + policy and UI checks (no root needed)
#   make verify       full integration suite (root, BTF kernel; see bench/verify.sh)
#   make dist         release tarball in dist/
#   make help         this list
PREFIX  ?= /usr/local
VERSION := $(shell cat VERSION)
ARCH    := $(shell uname -m)
DIST    := wisp-$(VERSION)-linux-$(ARCH)

.PHONY: all agent console test verify dist install install-console clean help

all: agent console

agent:
	$(MAKE) -C agent

console:
	$(MAKE) -C console

# Fast checks that need neither root nor a BPF-capable kernel.
test: agent console
	$(MAKE) -C console test tsan
	node --check console/web/assets/app.js
	@tmp=$$(mktemp -d) && sed -e "s|/etc/wisp/|$(CURDIR)/config/|g" config/wisp.conf \
	  | grep -vE '^[[:space:]]*(console|cert|key|ca)[[:space:]]*=' > $$tmp/wisp.conf \
	  && echo "netpolicy = $(CURDIR)/config/netpolicy.conf" >> $$tmp/wisp.conf \
	  && ./agent/wispd -c $$tmp/wisp.conf --check-config; rc=$$?; rm -rf $$tmp; exit $$rc

# End-to-end: detection, enforcement, CPU budget, rollout, forensics, ...
verify: all
	sudo bash bench/verify.sh

dist: all
	rm -rf dist/$(DIST) && mkdir -p dist/$(DIST)/bin dist/$(DIST)/config dist/$(DIST)/packaging dist/$(DIST)/docs
	cp agent/wispd console/wisp-console dist/$(DIST)/bin/
	cp config/*.conf dist/$(DIST)/config/
	cp packaging/*.service packaging/wisp.logrotate packaging/install.sh dist/$(DIST)/packaging/
	cp README.md CHANGELOG.md SECURITY.md VERSION dist/$(DIST)/
	cp docs/*.md dist/$(DIST)/docs/
	cd dist && tar czf $(DIST).tar.gz $(DIST) && sha256sum $(DIST).tar.gz > $(DIST).tar.gz.sha256
	@echo "dist/$(DIST).tar.gz"

# Sensor: binary, config, systemd unit; starts in monitor mode.
install: agent
	./packaging/install.sh

# Console: binary + unit. Put certificates and roles.conf in /etc/wisp/console
# first (docs/installation.md), then: systemctl enable --now wisp-console
install-console: console
	install -D -m0755 console/wisp-console $(DESTDIR)$(PREFIX)/bin/wisp-console
	install -D -m0644 packaging/wisp-console.service $(DESTDIR)/etc/systemd/system/wisp-console.service
	install -d -m0750 $(DESTDIR)/etc/wisp/console

clean:
	$(MAKE) -C agent clean
	$(MAKE) -C console clean
	rm -rf dist

help:
	@sed -n 's/^#   //p' Makefile
