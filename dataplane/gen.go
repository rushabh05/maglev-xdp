package dataplane

// Compiles ../bpf/lb.c and generates lb_bpfel.go (Go bindings for its maps,
// program and types) plus lb_bpfel.o (the compiled program, embedded in the
// Go binary). Needs clang and the Linux UAPI headers (the libbpf headers are
// vendored in bpf/include), so run it on Linux: `make generate` does it in
// the Docker image. The generated files are committed so the Go code builds
// without clang.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type stat -type sketch_params -type sketch_config -type heavy_entry -type hll_registers -type vip_key -type vip_info -type backend -type flow lb ../bpf/lb.c -- -I../bpf/include -O2 -g -Wall -Werror
