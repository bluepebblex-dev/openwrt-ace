package main

import (
	"reflect"
	"testing"
)

// Reconnect regression: the snapshot must never contain our own resolver.
// Restoring 127.0.0.1 after the core dies leaves the machine with no working
// DNS at all, which is worse than never having taken it over.
func TestWithoutLocalDNS(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", nil, nil},
		{"only ours means DHCP was the original", []string{"127.0.0.1"}, nil},
		{"dhcp plus ours", []string{"127.0.0.1", "223.5.5.5"}, []string{"223.5.5.5"}},
		{"user's own resolvers kept", []string{"192.168.1.1", "8.8.8.8"}, []string{"192.168.1.1", "8.8.8.8"}},
		{"ipv6 local untouched", []string{"::1"}, []string{"::1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := withoutLocalDNS(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("withoutLocalDNS(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
