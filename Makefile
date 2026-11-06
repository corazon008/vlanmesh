VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build run demo check test vet clean docker

all: build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/vlanmesh .

run: build
	./bin/vlanmesh -config config.demo.yaml

demo: build
	./bin/vlanmesh -config config.demo.yaml

once: build
	./bin/vlanmesh -config config.yaml -once

check: build
	./bin/vlanmesh -config config.yaml -check

test:
	go test ./...

vet:
	go vet ./...

checkall: vet test

docker:
	docker compose build

clean:
	rm -rf bin data
