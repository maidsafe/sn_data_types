SHELL := /bin/bash
SAFE_ND_VERSION := $(shell grep "^version" < Cargo.toml | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
UNAME_S := $(shell uname -s)
PWD := $(shell echo $$PWD)
UUID := $(shell uuidgen | sed 's/-//g')

build-container:
	rm -rf target/
	docker rmi -f maidsafe/safe-nd-build:${SAFE_ND_VERSION}
	docker build -f Dockerfile.build -t maidsafe/safe-nd-build:${SAFE_ND_VERSION} .

test:
ifeq ($(UNAME_S),Linux)
	docker run --name "safe-nd-build-${UUID}" -v "${PWD}":/usr/src/safe-nd:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-nd-build:${SAFE_ND_VERSION} \
		/bin/bash -c "cargo fmt -- --check --verbose && cargo clippy --verbose --release --all-targets && cargo test --verbose --release"
	docker cp "safe-nd-build-${UUID}":/target .
	docker rm "safe-nd-build-${UUID}"
else
	cargo fmt -- --check
	cargo test --verbose --release
endif
