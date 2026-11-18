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

	// 选中的版本（带 v 前缀，如 v1.19.34）。assetName 和直链都必须用它，
	// 不能写死 defaultVersion——否则选中最新版却去下旧版文件名。
	version := defaultVersion
	var urls []string
	if v, assetURL, err := pickAsset(client); err == nil && assetURL != "" {
		version = v
		urls = append(urls, assetURL)
	}
	assetName := "mihomo-" + osPartArch() + "-" + version + gzExt()
	expect, isPinned := pinnedCoreSHA256[assetName]
	direct := "https://github.com/MetaCubeX/mihomo/releases/download/" + version + "/" + assetName
	if isPinned {
		// Mirrors are only candidates for the pinned version: that is the one
		// whose bytes we can actually verify.
		urls = append(urls,
			direct,
			"https://ghfast.top/"+direct,
			"https://ghproxy.net/"+direct,
		)
	} else {
		// 新版本没有内嵌摘要，只走官方直链，不碰镜像（无校验的镜像不可信）。
		urls = append(urls, direct)
	}

	fmt.Fprintf(os.Stderr, "core: downloading %s into %s (%d source(s))\n",
		version, workDir, len(urls))

	var lastErr error
	for _, u := range urls {
		// 界面把 stderr 收进日志，用户在「下载内核」时能看到卡在哪个源
		fmt.Fprintf(os.Stderr, "core: fetching %s\n", u)
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "core:   failed: %v\n", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("core: download %s: HTTP %d", u, resp.StatusCode)
			fmt.Fprintf(os.Stderr, "core:   failed: HTTP %d\n", resp.StatusCode)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "core:   failed: %v\n", err)
			continue
		}
		if len(data) < 1024 {
			lastErr = fmt.Errorf("core: download %s: too small (%d bytes)", u, len(data))
			fmt.Fprintf(os.Stderr, "core:   failed: too small (%d bytes)\n", len(data))
			continue
		}
		if expect != "" {
			sum := sha256.Sum256(data)
			got := hex.EncodeToString(sum[:])
			if subtle.ConstantTimeCompare([]byte(got), []byte(expect)) != 1 {
				lastErr = fmt.Errorf("core: download %s: SHA256 mismatch (got %s…, want %s…), refusing to install", u, got[:12], expect[:12])
				fmt.Fprintf(os.Stderr, "core:   failed: SHA256 mismatch, refusing to install\n")
				continue
			}
			fmt.Fprintf(os.Stderr, "core:   sha256 ok (%s…)\n", got[:12])
		}
		if err := unpackArchive(data, workDir); err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "core:   unpack failed: %v\n", err)
			continue
		}
		fmt.Fprintf(os.Stderr, "core: installed %s (%d bytes from archive)\n", filepath.Join(workDir, ExeName()), len(data))
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
	// "下载并更新"承诺装最新版，所以先问 /latest。之前这里反过来——先找
	// pinned 的 defaultVersion，只有它 404 才查 latest——而 pinned tag 一直
	// 在，结果永远只装 1.19.32，界面却提示有 1.19.34，自相矛盾。
	req, _ := http.NewRequest(http.MethodGet, releasesAPI+"/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("latest release: HTTP %d", resp.StatusCode)
	}
	var r release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", err
	}
	if v, u, merr := matchingAsset(r); merr == nil {
		return v, u, nil
	}
	// latest 没有本架构资产：退回 pinned tag（它一定有）。
	if v, u, ok := releaseFor(client, defaultVersion); ok {
		return v, u, nil
	}
	return "", "", fmt.Errorf("no installable asset for %s", osPartArch())
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

// LatestVersion reports the newest mihomo tag GitHub publishes, stripped of the
// leading "v" so it compares directly with what the core prints for -v.
//
// Best effort by design: every failure path falls back to the pinned default
// instead of returning an error, because this only decorates a settings page.
// A "new version available" hint that breaks the page when GitHub is slow or
// blocked is worse than no hint at all. Callers pass a short timeout for the
// same reason - the probe it rides on runs while the user waits.
func LatestVersion(timeout time.Duration) string {
	fallback := strings.TrimPrefix(defaultVersion, "v")
	client := httpClient(timeout)
	req, err := http.NewRequest(http.MethodGet, releasesAPI+"/latest", nil)
	if err != nil {
		return fallback
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return fallback
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fallback
	}
	var r release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fallback
	}
	// Only report a tag we could actually install on this host; a release with
	// no asset for this arch is not an update the button could deliver.
	if _, _, err := matchingAsset(r); err != nil {
		return fallback
	}
	v := strings.TrimPrefix(strings.TrimSpace(r.TagName), "v")
	if v == "" {
		return fallback
	}
	return v
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
