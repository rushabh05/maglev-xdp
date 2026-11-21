package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/rushabh05/maglev-xdp/maglev"
)

func TestRunPrintsStatsAndChange(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"-n", "5", "-fail", "be-2", "-add", "be-6", "-flows", "10000"}, &out, &errOut)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, errOut.String())
	}
	for _, want := range []string{
		"M=65,537 (prime), N=5 backends",
		"be-1", "be-5",
		"balance: 13,107..13,108 slots per backend",
		"Change: fail be-2; add be-6 (N=5 -> 5",
		"slots remapped", "necessary", "extra",
		"Flows remapped (10,000 random flow hashes)",
		"hash mod N",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output is missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"-size", "100"}, &out, &errOut); !errors.Is(err, maglev.ErrSizeNotPrime) {
		t.Errorf("-size 100: err = %v, want %v", err, maglev.ErrSizeNotPrime)
	}
	if err := run([]string{"-n", "3", "-fail", "nope"}, &out, &errOut); !errors.Is(err, maglev.ErrNotFound) {
		t.Errorf("-fail nope: err = %v, want %v", err, maglev.ErrNotFound)
	}
	if err := run([]string{"-backends", "a,b", "-add", "a"}, &out, &errOut); !errors.Is(err, maglev.ErrDuplicate) {
		t.Errorf("-add existing: err = %v, want %v", err, maglev.ErrDuplicate)
	}
}

func TestCommas(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 65537: "65,537", 1234567: "1,234,567"} {
		if got := commas(n); got != want {
			t.Errorf("commas(%d) = %q, want %q", n, got, want)
		}
	}
}
