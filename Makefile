# Wisp EDR -- top-level build.
#
#   make              build the sensor (eBPF) and the console
#   make test         unit tests + policy and UI checks (no root needed)
#   make verify       integration suite (root, BTF kernel; a disposable test VM,
#                     never a production host; see bench/verify.sh)
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
	  && ./agent/wispd -c $$tmp/wisp.conf --check-config; rc=$$?; rm -rf $$tmp; exit $$rc

# End-to-end: detection, enforcement, CPU budget, rollout, forensics, ...
# VERIFY_FLAGS=--force runs it even where a wispd or wisp-console is
# installed or running (it still only touches its own processes and files).
verify: all
	sudo bash bench/verify.sh $(VERIFY_FLAGS)

# Release tarball. Binaries are stripped (debug info is kept in
# dist/$(DIST)-debug/ and linked with .gnu_debuglink); the archive is
# reproducible: sorted, fixed owner, mtime = SOURCE_DATE_EPOCH (default: the
# last commit's time), gzip without a timestamp.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
DIST_DOCS := README.md CHANGELOG.md SECURITY.md CONTRIBUTING.md BENCHMARKS.md PARITY.md VERSION $(wildcard LICENSE)
dist: all
	rm -rf dist/$(DIST) dist/$(DIST)-debug && mkdir -p dist/$(DIST)/bin dist/$(DIST)/config \
	  dist/$(DIST)/packaging dist/$(DIST)/docs/images dist/$(DIST)/bench dist/$(DIST)/sdk dist/$(DIST)/mcp \
	  dist/$(DIST)-debug
	for b in agent/wispd console/wisp-console; do n=$$(basename $$b); \
	  objcopy --only-keep-debug $$b dist/$(DIST)-debug/$$n.debug && \
	  objcopy --strip-debug --strip-unneeded --add-gnu-debuglink=dist/$(DIST)-debug/$$n.debug \
	    $$b dist/$(DIST)/bin/$$n || exit 1; done
	cp config/*.conf dist/$(DIST)/config/
	cp packaging/*.service packaging/*.timer packaging/wisp.logrotate packaging/install.sh dist/$(DIST)/packaging/
	cp $(DIST_DOCS) dist/$(DIST)/
	cp docs/*.md dist/$(DIST)/docs/
	cp docs/images/* dist/$(DIST)/docs/images/ 2>/dev/null || true
	cp bench/mkpki.sh bench/tpm_identity_demo.sh dist/$(DIST)/bench/
	cp sdk/wisp.py sdk/wisp.ts dist/$(DIST)/sdk/
	cp mcp/wisp_mcp.py dist/$(DIST)/mcp/
	cd dist && for d in $(DIST) $(DIST)-debug; do \
	  tar --sort=name --mtime=@$(SOURCE_DATE_EPOCH) --owner=0 --group=0 --numeric-owner --mode=u+rwX,go+rX,go-w \
	    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime -cf - $$d \
	    | gzip -9n > $$d.tar.gz || exit 1; done && \
	  sha256sum $(DIST).tar.gz $(DIST)-debug.tar.gz > $(DIST).tar.gz.sha256
	@echo "dist/$(DIST).tar.gz"

# Sensor: binary, config, systemd unit; starts in monitor mode.
install: agent
	$(if $(DESTDIR),mkdir -p $(DESTDIR) &&) PREFIX=$(PREFIX) ./packaging/install.sh $(if $(DESTDIR),--root $(DESTDIR) --no-start)

# Console: binary, unit (paths follow PREFIX), /etc/wisp/console, docs and a
# daemon-reload; the same code path as the release tarball's
# `packaging/install.sh --console`. Put certificates and roles.conf in
# /etc/wisp/console first (docs/installation.md), then:
# systemctl enable --now wisp-console
install-console: console
	$(if $(DESTDIR),mkdir -p $(DESTDIR) &&) PREFIX=$(PREFIX) ./packaging/install.sh --console $(if $(DESTDIR),--root $(DESTDIR))

clean:
	$(MAKE) -C agent clean
	$(MAKE) -C console clean
	rm -rf dist

help:
	@sed -n 's/^#   //p' Makefile
