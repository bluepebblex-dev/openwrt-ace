//go:build !darwin

package core

// DNS takeover is a macOS TUN concern. Elsewhere the resolver already follows
// the tunnel, or capture is done with the system proxy instead.
func SetSystemDNS(string, []string) error { return nil }
func RestoreSystemDNS(string) error       { return nil }
func SystemDNSServers(string) []string    { return nil }
func DNSPointsAtLocal(string) bool        { return false }
func FlushDNSCache()                      {}
