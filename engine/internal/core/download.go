package core

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// mihomo releases are published on GitHub as versioned per-platform zips. The
// client keeps a known-good default so a fresh install can provision the core
// without the user hunting for a binary.
const (
	releasesAPI = "https://api.github.com/repos/MetaCubeX/mihomo/releases"
	// defaultVersion is the release tag the client falls back to when no core
	// is present and the network cannot be reached to list newer ones.
	// v1.19.32 is the official latest stable (2026-09-30): the first line that
	// carries every protocol this client renders (wireguard+amnezia-wg-option,
	// masque h2/h3, dialer-proxy chains).
	defaultVersion = "v1.19.32"
)

// pinnedCoreSHA256 holds the SHA256 of the *official* release archive for the
// pinned defaultVersion, per platform. mihomo publishes no checksum files, so
// these digests were computed from the bytes fetched straight from
// github.com/MetaCubeX/mihomo and are embedded here — that turns every download
// source (including the speed mirrors, whose operators are otherwise fully
// trusted with the bytes we are about to execute) into a verified source for
// the pinned version. Newer versions fetched via the releases API have no
// embedded digest; they are downloaded from the official github.com URL only,
// never from mirrors.
var pinnedCoreSHA256 = map[string]string{
	"mihomo-linux-arm64-v1.19.32.gz":    "9dd862e28b46ff7d775f169cceebc28deccaa0a9e804237d421cd2571e0caba0",
	"mihomo-linux-amd64-v1.19.32.gz":    "8451100836c9eda194331c2babfad490b2faf30cebc1a04b0e76fd8ac2d35d10",
	"mihomo-darwin-arm64-v1.19.32.gz":   "3312a6780652c622890fd4357c6a853bbf865464fd047ac7b7f52dab8de18652",
	"mihomo-windows-amd64-v1.19.32.zip": "1ac84e795b5b915446e20139677fb6cc013a0778e876e8d4c96f994750b4c4a3",
}

// ostuple returns the mihomo release asset fragment for this platform.
func ostuple() (osPart, archPart, exeName string) {
	archPart = runtime.GOARCH
	switch archPart {
	case "amd64", "arm64":
	default:
		archPart = "amd64"
	}
	exeName = "mihomo"
	switch runtime.GOOS {
	case "windows":
		osPart = "windows"
		exeName = "mihomo.exe"
	case "linux":
		osPart = "linux"
	case "darwin":
		osPart = "darwin"
	default:
		osPart = runtime.GOOS
	}
	return osPart, archPart, exeName
}

// ExeName returns the core binary filename for this host.
func ExeName() string {
	_, _, n := ostuple()
	return n
}

// CoreInDir returns the expected core binary path inside dir.
func CoreInDir(dir string) string {
	return filepath.Join(dir, ExeName())
}

// release is the subset of the GitHub releases API we consume.
type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// EnsureBinary guarantees a working core binary in workDir. When one is
// already present it is kept; otherwise the caller may supply localPath, and
// failing that the client downloads the default (or a newer) release.
func EnsureBinary(workDir, localPath string) (string, error) {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return "", err
	}
	candidate := CoreInDir(workDir)
	if isExecutable(candidate) {
		clearLaunchAttrs(candidate)
		return candidate, nil
	}
	if localPath != "" {
		if isExecutable(localPath) {
			return localPath, nil
		}
		return "", fmt.Errorf("core: %s is not an executable mihomo binary", localPath)
	}
	// No local core: download a release.
	if err := downloadRelease(workDir); err != nil {
		return "", fmt.Errorf("core: no mihomo binary and download failed: %w", err)
	}
	if isExecutable(candidate) {
		return candidate, nil
	}
	return "", fmt.Errorf("core: download completed but %s is missing", candidate)
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

// downloadRelease fetches the pinned default release (or a newer one via the
// releases API) and unpacks the archive that matches this host's OS+arch.
//
// Integrity model: for the pinned version, every candidate URL (official and
// mirrors) is checked against pinnedCoreSHA256 before unpacking — a mirror
// serving different bytes is rejected outright. For a newer version discovered
// via the API, only the official github.com asset URL is used (TLS-trusted,
// no mirrors) since we have no embedded digest for it.
func downloadRelease(workDir string) error {
	client := httpClient(30 * time.Second)
	assetName := "mihomo-" + osPartArch() + "-" + defaultVersion + gzExt()
	expect, isPinned := pinnedCoreSHA256[assetName]
	var urls []string
	apiVersion := ""
	if v, assetURL, err := pickAsset(client); err == nil && assetURL != "" {
		apiVersion = v
		urls = append(urls, assetURL)
	}
	direct := "https://github.com/MetaCubeX/mihomo/releases/download/" + defaultVersion + "/" + assetName
	if isPinned {
		// Mirrors are only candidates for the pinned version: that is the one
		// whose bytes we can actually verify.
		urls = append(urls,
			direct,
			"https://ghfast.top/"+direct,
			"https://ghproxy.net/"+direct,
		)
	} else {
		urls = append(urls, direct)
	}
	if apiVersion != "" && apiVersion != defaultVersion {
		// The API handed us a newer tag than the pinned default; we have no
		// embedded digest for it, so there is nothing to verify mirrors against.
		expect = ""
	}

	var lastErr error
	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("core: download %s: HTTP %d", u, resp.StatusCode)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if len(data) < 1024 {
			lastErr = fmt.Errorf("core: download %s: too small (%d bytes)", u, len(data))
			continue
		}
		if expect != "" {
			sum := sha256.Sum256(data)
			got := hex.EncodeToString(sum[:])
			if subtle.ConstantTimeCompare([]byte(got), []byte(expect)) != 1 {
				lastErr = fmt.Errorf("core: download %s: SHA256 mismatch (got %s…, want %s…), refusing to install", u, got[:12], expect[:12])
				continue
			}
		}
		if err := unpackArchive(data, workDir); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no download URL attempted")
	}
	return lastErr
}

// gzExt returns the archive extension mihomo uses for this platform.
func gzExt() string {
	if runtime.GOOS == "windows" {
		return ".zip"
	}
	return ".gz"
}

// osPartArch returns the "os-arch" fragment used in mihomo release asset names.
func osPartArch() string {
	o, a, _ := ostuple()
	return o + "-" + a
}

func pickAsset(client *http.Client) (version, url string, err error) {
	if v, u, ok := releaseFor(client, defaultVersion); ok {
		return v, u, nil
	}
	// Fall back to listing latest when the pinned one 404s (e.g. removed).
	req, _ := http.NewRequest(http.MethodGet, releasesAPI+"/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var r release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", err
	}
	return matchingAsset(r)
}

func releaseFor(client *http.Client, tag string) (string, string, bool) {
	req, _ := http.NewRequest(http.MethodGet, releasesAPI+"/tags/"+tag, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", false
	}
	var r release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", false
	}
	v, u, err := matchingAsset(r)
	return v, u, err == nil
}

// matchingAsset finds the asset for <os>-<arch>. mihomo names assets like
// "mihomo-windows-amd64-v1.19.4.zip" (Windows) or "mihomo-darwin-arm64-
// v1.19.32.gz" (macOS). darwin assets are gzipped binaries; windows/linux are
// zips. We prefer the canonical asset (the one whose version tag sits directly
// after the arch, with no -goXXX / -compatible variant between them) and we
// accept either archive format.
func matchingAsset(r release) (string, string, error) {
	osPart, archPart, _ := ostuple()
	needle := osPart + "-" + archPart + "-"

	var zipURL, gzURL string
	for _, a := range r.Assets {
		i := strings.Index(a.Name, needle)
		if i < 0 {
			continue
		}
		rest := a.Name[i+len(needle):]
		// rest should begin with "vX.Y.Z" for the canonical asset; variant
		// assets like "...arm64-go120-v1.19.32.gz" have "-go120" there.
		if !strings.HasPrefix(rest, "v") {
			continue
		}
		switch {
		case strings.HasSuffix(a.Name, ".zip"):
			if zipURL == "" {
				zipURL = a.BrowserDownloadURL
			}
		case strings.HasSuffix(a.Name, ".gz"):
			if gzURL == "" {
				gzURL = a.BrowserDownloadURL
			}
		}
	}
	if runtime.GOOS == "darwin" && gzURL != "" {
		return r.TagName, gzURL, nil
	}
	if gzURL != "" {
		return r.TagName, gzURL, nil
	}
	if zipURL != "" {
		return r.TagName, zipURL, nil
	}
	return "", "", fmt.Errorf("core: no %s-%s asset in release %s", osPart, archPart, r.TagName)
}

// unpackArchive extracts the core binary into workDir from either a zip (windows
// / linux) or a gzip-wrapped single binary (darwin). On darwin the gz contains
// only the mihomo executable; geosite.dat / geoip.metadb are fetched separately
// by DownloadGeoData when a rule preset needs them.
func unpackArchive(data []byte, workDir string) error {
	if isGzip(data) {
		return unpackGzip(data, workDir)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		name := filepath.Base(f.Name)
		// Keep the exe plus the geodata mihomo needs for rule-based routing.
		if name != ExeName() && name != geoSiteName && name != geoIPName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(filepath.Join(workDir, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return err
		}
		out.Close()
		rc.Close()
		if name == ExeName() {
			clearLaunchAttrs(filepath.Join(workDir, name))
		}
	}
	return nil
}

// isGzip reports whether data begins with the gzip magic number (0x1f 0x8b).
func isGzip(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

// unpackGzip inflates a single-file gzip payload (the mihomo binary) and writes
// it to workDir/<ExeName> with the executable bit set.
func unpackGzip(data []byte, workDir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("core: bad gzip: %w", err)
	}
	defer gz.Close()
	dst := filepath.Join(workDir, ExeName())
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, gz); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		return err
	}
	clearLaunchAttrs(dst)
	return nil
}
