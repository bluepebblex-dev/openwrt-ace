package core

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"time"
)

// GeoFileInfo is one geo database as the UI wants to show it: present or not,
// how big, and which version of the data it carries.
//
// The two databases answer the version question differently, and the UI must
// not pretend otherwise:
//
//   - geoip.metadb is a MaxMind DB. Its metadata trailer records build_epoch,
//     the moment MetaCubeX generated the data — a real version.
//   - geosite.dat is the v2ray geosite format, a bare protobuf list of domains
//     with no version field anywhere. The only honest signal is the file's own
//     modification time, i.e. when this router downloaded it.
//
// VersionNote tells the caller which of the two it is looking at, so the page
// can label the geosite date as a download date instead of selling it as a
// database version.
type GeoFileInfo struct {
	Name        string `json:"name"`
	Present     bool   `json:"present"`
	Size        int64  `json:"size"`
	Version     string `json:"version,omitempty"`
	VersionNote string `json:"version_note,omitempty"`
}

// InspectGeoData returns the state of every database mihomo needs, in the same
// order as GeoDataNames. A directory that cannot be read yields a list of
// absent files rather than an error: "missing" is a valid answer for the UI.
func InspectGeoData(dir string) []GeoFileInfo {
	out := make([]GeoFileInfo, 0, len(geoAssets))
	for _, a := range geoAssets {
		info := GeoFileInfo{Name: a.Name}
		path := filepath.Join(dir, a.Name)
		fi, err := os.Stat(path)
		if err == nil && fi.Mode().IsRegular() {
			info.Size = fi.Size()
			info.Present = fi.Size() >= a.Min
			if info.Present {
				if a.Name == "geoip.metadb" {
					if ts, ok := mmdbBuildEpoch(path); ok {
						info.Version = ts.UTC().Format("2006-01-02")
						info.VersionNote = "数据库构建日期（读自 geoip.metadb 内部 build_epoch）"
					}
				}
				if info.Version == "" {
					info.Version = fi.ModTime().UTC().Format("2006-01-02")
					info.VersionNote = "该文件不含版本号，显示的是下载日期"
				}
			}
		}
		out = append(out, info)
	}
	return out
}

// mmdbMarker starts the metadata section at the tail of every MaxMind DB.
var mmdbMarker = []byte("\xab\xcd\xefMaxMind.com")

// mmdbMetaWindow is how much of the tail is searched for the marker. The spec
// caps the metadata section at 128 KB.
const mmdbMetaWindow = 128 * 1024

// mmdbBuildEpoch pulls build_epoch out of the metadata map. Only that one
// uint64 is decoded — walking the whole map would mean a general MMDB decoder
// for a single date we then format and forget.
func mmdbBuildEpoch(path string) (time.Time, bool) {
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}, false
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.Size() < int64(len(mmdbMarker)) {
		return time.Time{}, false
	}
	n := int64(mmdbMetaWindow)
	if fi.Size() < n {
		n = fi.Size()
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, fi.Size()-n); err != nil {
		return time.Time{}, false
	}

	idx := bytes.LastIndex(buf, mmdbMarker)
	if idx < 0 {
		return time.Time{}, false
	}
	data := buf[idx+len(mmdbMarker):]

	// Map keys are utf8 strings, so the key bytes appear verbatim; the value
	// ctrl byte sits right after the key.
	key := []byte("build_epoch")
	k := bytes.Index(data, key)
	if k < 0 {
		return time.Time{}, false
	}
	secs, ok := mmdbUint(data[k+len(key):])
	if !ok || secs <= 0 {
		return time.Time{}, false
	}
	ts := time.Unix(int64(secs), 0)
	// A bogus epoch (corrupt file) would render as year 1 or 9999; refuse it
	// so the UI falls back to the download date instead of printing nonsense.
	if ts.Year() < 2015 || ts.Year() > 2100 {
		return time.Time{}, false
	}
	return ts, true
}

// mmdbUint decodes one unsigned integer data field. Layout: a control byte
// carrying type in the top three bits and size in the bottom five; types above
// 7 escape through a second "extended type" byte. uint16/32/64 store their
// value big-endian in as many bytes as the size says.
func mmdbUint(b []byte) (uint64, bool) {
	if len(b) < 2 {
		return 0, false
	}
	ctrl := b[0]
	typ := int(ctrl >> 5)
	size := int(ctrl & 0x1f)
	i := 1
	if typ == 0 {
		typ = int(b[1]) + 7
		i = 2
	}
	switch size {
	case 29:
		if i >= len(b) {
			return 0, false
		}
		size = 29 + int(b[i])
		i++
	case 30:
		if i+1 >= len(b) {
			return 0, false
		}
		size = 285 + int(binary.BigEndian.Uint16(b[i:]))
		i += 2
	case 31:
		if i+2 >= len(b) {
			return 0, false
		}
		size = 65821 + int(b[i])<<16 + int(b[i+1])<<8 + int(b[i+2])
		i += 3
	}
	if typ != 5 && typ != 6 && typ != 9 { // uint16 / uint32 / uint64
		return 0, false
	}
	if size <= 0 || size > 8 || i+size > len(b) {
		return 0, false
	}
	var v uint64
	for j := 0; j < size; j++ {
		v = v<<8 | uint64(b[i+j])
	}
	return v, true
}
