# wisp-console (C++20). Needs: g++ >= 10 or clang >= 12, OpenSSL 3 (libssl-dev),
# nlohmann/json 3.x (nlohmann-json3-dev).
#
#   make            build wisp-console
#   make test       unit tests under AddressSanitizer + UndefinedBehaviorSanitizer
#   make tsan       unit tests under ThreadSanitizer
#   make clean
CXX      ?= g++
VERSION  := $(shell cat ../VERSION 2>/dev/null || echo dev)
WARN     := -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Wcast-align -Wformat=2
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++20 $(WARN) -pthread -DWISP_VERSION='"$(VERSION)"' -Isrc -Ibuild
# Production hardening for a network-facing service.
HARDEN   := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDHARDEN := -pie -Wl,-z,relro,-z,now
LIBS     := -lssl -lcrypto -pthread

CORE   := src/util.cpp src/model.cpp src/rbac.cpp src/vault.cpp src/vulndb.cpp src/store.cpp \
          src/net.cpp src/http.cpp src/analysis.cpp src/ai.cpp build/assets.cpp
APP    := src/console.cpp
ASSETS := web/index.html $(wildcard web/assets/*) vulndb.json
HDRS   := $(wildcard src/*.hpp)

.PHONY: all test tsan clean

all: wisp-console

build/embed: tools/embed.cpp
	@mkdir -p build
	$(CXX) -O1 -std=c++20 -o $@ $<

build/assets.cpp: build/embed $(ASSETS)
	build/embed $@ . $(ASSETS)

# Objects are rebuilt when headers, the version or flags change.
build/%.o: src/%.cpp $(HDRS) ../VERSION | build/assets.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(HARDEN) -c -o $@ $<

build/assets.o: build/assets.cpp src/assets.hpp
	$(CXX) $(CXXFLAGS) $(HARDEN) -c -o $@ $<

OBJS := $(patsubst src/%.cpp,build/%.o,$(filter src/%,$(CORE) $(APP))) build/assets.o

wisp-console: $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDHARDEN) -o $@ $^ $(LIBS)

# Tests link the same sources (minus main) with sanitizers.
# GCC 13 reports false -Wmaybe-uninitialized inside libstdc++'s <regex> at -O1
# with sanitizers; the release build (-O2) is warning-clean without this.
TESTWARN := -Wno-maybe-uninitialized
TEST_SRC := tests/console_test.cpp tests/analysis_test.cpp $(CORE) $(APP)
build/test-asan: $(TEST_SRC) $(HDRS) tests/harness.hpp build/assets.cpp
	$(CXX) $(CXXFLAGS) $(TESTWARN) -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all \
	  -DWISP_NO_MAIN -o $@ $(TEST_SRC) $(LIBS)

build/test-tsan: $(TEST_SRC) $(HDRS) tests/harness.hpp build/assets.cpp
	$(CXX) $(CXXFLAGS) $(TESTWARN) -O1 -fsanitize=thread -DWISP_NO_MAIN -o $@ $(TEST_SRC) $(LIBS)

test: build/test-asan
	./build/test-asan

tsan: build/test-tsan
	TSAN_OPTIONS=halt_on_error=1 ./build/test-tsan

clean:
	rm -rf build wisp-console
