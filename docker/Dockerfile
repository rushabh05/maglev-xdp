# Linux build and test environment for the XDP data plane. XDP can't run on
# macOS, so `make generate`, `make docker-test` and `make e2e` run in here.
#
# clang comes from a prebuilt image rather than apt: the Debian package
# mirror is very slow from the network this was developed on, Docker Hub
# isn't. The libbpf headers are vendored in bpf/include, so only the kernel
# UAPI headers (already in the image) are needed from the system.
FROM golang:1.26-trixie AS go

FROM silkeh/clang:19
COPY --from=go /usr/local/go /usr/local/go
ENV GOPATH=/go PATH=/go/bin:/usr/local/go/bin:$PATH CC=clang

# clang -target bpf doesn't search the multiarch directory that holds
# <asm/types.h>, which the kernel UAPI headers include.
RUN ln -s "/usr/include/$(uname -m)-linux-gnu/asm" /usr/include/asm

# For scripts/e2e.sh (network namespaces, veth, bridge).
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
