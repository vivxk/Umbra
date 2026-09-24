.PHONY: all build install uninstall test lint clippy fmt check clean

CARGO ?= cargo

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
	@sudo bash scripts/install.sh

uninstall:
	@sudo bash scripts/uninstall.sh

clean:
	$(CARGO) clean
