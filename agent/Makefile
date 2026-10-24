CC      ?= cc
CLANG   ?= clang
BPFTOOL ?= $(firstword $(wildcard /usr/lib/linux-tools-*/bpftool) /usr/sbin/bpftool bpftool)
CFLAGS  ?= -O2 -g -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-format-truncation -D_GNU_SOURCE
LDFLAGS ?=
PREFIX  ?= /usr/local

# Event source: bpf (default, needs libbpf + a BTF kernel) or connector
# (portable fallback, netlink proc connector, reads /proc per event).
SENSOR  ?= bpf

# eBPF target architecture for CO-RE tracepoint argument access.
BPF_ARCH := $(patsubst aarch64,arm64,$(patsubst x86_64,x86,$(shell uname -m)))

# One version for the whole product, from ../VERSION.
VERSION := $(shell cat ../VERSION 2>/dev/null || echo dev)
CFLAGS  += -DWISP_VERSION='"$(VERSION)"'

COMMON  := main.c util.c config.c actor.c rules.c catalog.c inventory.c fim.c respond.c output.c console.c pipeline.c identity.c governor.c ecosystem.c netpolicy.c patch.c anomaly.c forensics.c

ifeq ($(SENSOR),bpf)
  SRC    := $(COMMON) proc_bpf.c
  LIBS   := -lssl -lcrypto -lbpf -lelf -lz -pthread
  BPFDEP := bpf/exec.skel.h
  CFLAGS += -DWISP_SENSOR_BPF
else
  SRC    := $(COMMON) proc.c
  LIBS   := -lssl -lcrypto -pthread
  BPFDEP :=
endif

OBJ := $(SRC:.c=.o)

# The sensor choice changes CFLAGS and the source list, so it is a build
# input: switching SENSOR must rebuild every object and relink, never reuse a
# binary or objects built for the other sensor.
STAMP := .sensor-$(SENSOR)
$(STAMP):
	rm -f .sensor-*
	touch $@

wispd: $(STAMP) $(BPFDEP) $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

# A recipe that fails must not leave a partial target behind (an empty
# vmlinux.h or skeleton would otherwise break every later build).
.DELETE_ON_ERROR:

# --- eBPF object + CO-RE skeleton -----------------------------------------
# Generated headers are written to a temporary file and moved into place only
# on success, so an interrupted or failed bpftool run never leaves a stale or
# empty file that make would consider up to date.
bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp || { rm -f $@.tmp; false; }
	test -s $@.tmp || { rm -f $@.tmp; false; }
	mv -f $@.tmp $@

bpf/exec.bpf.o: bpf/exec.bpf.c bpf/vmlinux.h
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Ibpf -c $< -o $@

bpf/exec.skel.h: bpf/exec.bpf.o
	$(BPFTOOL) gen skeleton $< name exec_bpf > $@.tmp || { rm -f $@.tmp; false; }
	test -s $@.tmp || { rm -f $@.tmp; false; }
	mv -f $@.tmp $@

proc_bpf.o: proc_bpf.c bpf/exec.skel.h wisp.h $(STAMP) ../VERSION
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c wisp.h $(STAMP) ../VERSION
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(COMMON:.c=.o) proc.o proc_bpf.o wispd bpf/exec.bpf.o bpf/exec.skel.h \
	      bpf/vmlinux.h bpf/*.tmp .sensor-*

install: wispd
	install -D -m0755 wispd $(DESTDIR)$(PREFIX)/sbin/wispd

.PHONY: clean install

# Cross-compile check for the non-Linux sensor backends against their real SDK
# headers. Verifies API correctness; it does not produce runnable binaries
# (that needs the target OS). Windows uses the MinGW-w64 Windows headers.
.PHONY: check-platform
check-platform:
	@command -v x86_64-w64-mingw32-gcc >/dev/null && { \
	  x86_64-w64-mingw32-gcc -c -I. -Iplatform -D_GNU_SOURCE \
	    platform/sensor_windows.c -o /tmp/wisp_sensor_windows.o 2>/dev/null \
	  && echo "windows (ETW) backend: compiles against Windows SDK headers (MinGW)"; } \
	  || echo "windows backend: install mingw-w64 to cross-compile-check"
	@command -v clang >/dev/null && { \
	  clang -fsyntax-only -fblocks -x objective-c -Iplatform -Iplatform/shim -I. \
	    platform/sensor_macos.m 2>/dev/null \
	  && echo "macos (EndpointSecurity) backend: compiles against documented ES API (clang); links Apple's framework on macOS"; } \
	  || echo "macos backend: install clang to syntax-check"
