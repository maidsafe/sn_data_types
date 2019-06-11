SHELL := /bin/bash
SAFE_ND_VERSION := $(shell grep "^version" < Cargo.toml | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')

build-container:
	rm -rf target/
	docker rmi -f maidsafe/safe-nd-build:${SAFE_ND_VERSION}
	docker build -f Dockerfile.build -t maidsafe/safe-nd-build:${SAFE_ND_VERSION} .
