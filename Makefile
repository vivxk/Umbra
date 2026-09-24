.PHONY: all build install uninstall test lint clippy fmt check clean

CARGO ?= cargo
DESTDIR ?=
PREFIX ?= /usr

all: build

build:
	$(CARGO) build --release

test:
	$(CARGO) test

lint: clippy fmt

clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

fmt:
	$(CARGO) fmt --check

install: build
	@if [ "$$(id -u)" -eq 0 ]; then \
		DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)" bash scripts/install.sh; \
	else \
		sudo DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)" bash scripts/install.sh; \
	fi

uninstall:
	@if [ "$$(id -u)" -eq 0 ]; then \
		DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)" bash scripts/uninstall.sh; \
	else \
		sudo DESTDIR="$(DESTDIR)" PREFIX="$(PREFIX)" bash scripts/uninstall.sh; \
	fi

clean:
	$(CARGO) clean
