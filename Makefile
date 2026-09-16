POOLS_DIR ?= $(CURDIR)/soroban-privacy-pools
PTAU_PATH ?= $(CURDIR)/ptau/pot20_final.ptau
OUTPUT_DIR ?= $(CURDIR)/artifacts
GENERATED_DIR ?= $(CURDIR)/generated

.PHONY: submodule sdk-build \
	shape-2x2 shape-2x2-delegated shape-6x6 shape-6x6-delegated shapes

submodule:
	git submodule update --init --recursive

sdk-build:
	cd client-sdk && npm i && npm run build

shape-2x2:
	./scripts/build-shape.sh 2x2 direct

shape-2x2-delegated:
	./scripts/build-shape.sh 2x2 delegated

shape-6x6:
	./scripts/build-shape.sh 6x6 direct

shape-6x6-delegated:
	./scripts/build-shape.sh 6x6 delegated

shapes: shape-2x2 shape-2x2-delegated shape-6x6 shape-6x6-delegated
