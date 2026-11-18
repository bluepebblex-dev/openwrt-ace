//go:build !windows

package main

import "fmt"

// shortVersion is the label the About page and headers use. On non-Windows
// builds there is no GUI string table, so a dev build reports a plain "dev".
func shortVersion() string {
	if v := resolveVersion(); v != "dev" {
		return "v" + v
	}
	return "v" + resolveVersion()
}

// tr is the i18n seam. The non-Windows build has no GUI string table; the CLI
// is authored in Chinese and vpngate.go only uses tr for two display tags, so
// returning the key verbatim is correct.
func tr(s string) string { return s }

// trf is the formatting i18n seam (unused off-Windows, kept for parity).
func trf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
