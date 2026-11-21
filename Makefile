# XDP only runs on Linux. On macOS, the docker-* targets run in a privileged
# Linux container (Docker Desktop's VM kernel); on Linux they work the same.

IMAGE      := maglev-xdp-dev
DOCKER_RUN := docker run --rm --privileged \
	-v "$(CURDIR)":/src -w /src \
	-v maglev-xdp-gomod:/go/pkg/mod -v maglev-xdp-gocache:/root/.cache/go-build \
	$(IMAGE)

.PHONY: test image generate docker-test e2e

## test: Go tests that run anywhere; the data-plane tests skip off Linux
test:
	go test ./...

## image: build the Linux dev image (Go, clang, libbpf, iproute2)
image:
	docker build -t $(IMAGE) -f docker/Dockerfile docker

## generate: compile bpf/lb.c and regenerate the Go bindings
generate: image
	$(DOCKER_RUN) go generate ./dataplane

## docker-test: every test, including the XDP program in the kernel
docker-test: image
	$(DOCKER_RUN) go test -race -count=1 -v ./...

## e2e: attach to a veth and forward real packets, in both forwarding modes
e2e: image
	$(DOCKER_RUN) sh -c './scripts/e2e.sh l2 && ./scripts/e2e.sh ipip'
