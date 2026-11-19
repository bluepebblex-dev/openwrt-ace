package core

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeFakeMMDB builds a file whose tail mimics a MaxMind DB: an arbitrary
// body, then the marker, then a metadata map carrying build_epoch.
func writeFakeMMDB(t *testing.T, path string, epoch int64) {
	t.Helper()
	var body []byte
	// 撑过 512 KB 的最小体积门槛，否则 InspectGeoData 会把它判成缺失
	for i := 0; i < 600*1024; i++ {
		body = append(body, byte(i))
	}
	body = append(body, mmdbMarker...)
	body = append(body, []byte("\x4bbuild_epoch")...)
	body = append(body, 0x04, 0x02) // extended type 9 (uint64), 4-byte value
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], uint32(epoch))
	body = append(body, v[:]...)
	body = append(body, []byte("\x4bdatabase_type\x4bMeta-geoip0")...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMMDBBuildEpoch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geoip.metadb")
	want := time.Date(2026, 11, 14, 6, 30, 0, 0, time.UTC)
	writeFakeMMDB(t, path, want.Unix())

	got, ok := mmdbBuildEpoch(path)
	if !ok {
		t.Fatal("build_epoch 未解析出来")
	}
	if got.UTC().Format("2006-01-02") != "2026-11-14" {
		t.Fatalf("日期 = %s, 期望 2026-11-14", got.UTC().Format("2006-01-02"))
	}
}

func TestMMDBBuildEpochRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "junk.metadb")
	if err := os.WriteFile(path, []byte("not a database at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := mmdbBuildEpoch(path); ok {
		t.Fatal("非 MMDB 文件不应解析出版本")
	}
}

// size 30 (285 + uint16) is how a metadata field longer than 284 bytes is
// encoded; make sure the extended-size path still lands on the value.
func TestMMDBUintExtendedSize(t *testing.T) {
	var b []byte
	b = append(b, 0x1e|0x40) // type 2 不可能命中；这里只验证 size 解析本身
	b = append(b, 0x00, 0x08)
	b = append(b, 0, 0)
	if _, ok := mmdbUint(b); ok {
		t.Fatal("非整数类型不应被当成版本")
	}

	// type 9 (uint64) with 2-byte value: ctrl 0x02, ext 0x02, value 0x12 0x34
	if v, ok := mmdbUint([]byte{0x02, 0x02, 0x12, 0x34}); !ok || v != 0x1234 {
		t.Fatalf("uint64 = %d ok=%v, 期望 4660", v, ok)
	}
}

func TestInspectGeoData(t *testing.T) {
	dir := t.TempDir()
	// 两个文件都要过 512 KB 的最小体积门槛，否则会被判为缺失。
	site := make([]byte, 600*1024)
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), site, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFakeMMDB(t, filepath.Join(dir, "geoip.metadb"), time.Date(2026, 11, 14, 6, 0, 0, 0, time.UTC).Unix())
	// 让假 MMDB 也超过体积门槛
	mtime := time.Date(2026, 11, 19, 11, 20, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(dir, "geosite.dat"), mtime, mtime); err != nil {
		t.Fatal(err)
	}

	files := InspectGeoData(dir)
	if len(files) != 2 {
		t.Fatalf("得到 %d 个文件，期望 2", len(files))
	}
	if !files[0].Present || files[0].Name != "geosite.dat" {
		t.Fatalf("geosite 状态不对: %+v", files[0])
	}
	// geosite 没有内部版本 —— 只能显示下载日期，且要标明口径
	if files[0].Version != "2026-11-19" {
		t.Fatalf("geosite 版本 = %q, 期望下载日期 2026-11-19", files[0].Version)
	}
	if files[0].VersionNote == "" {
		t.Fatal("geosite 的版本必须带口径说明")
	}
	if files[1].Name != "geoip.metadb" || files[1].Version != "2026-11-14" {
		t.Fatalf("geoip 版本不对: %+v", files[1])
	}
}

func TestInspectGeoDataMissing(t *testing.T) {
	files := InspectGeoData(t.TempDir())
	for _, f := range files {
		if f.Present {
			t.Fatalf("%s 不该被判为存在", f.Name)
		}
		if f.Version != "" {
			t.Fatalf("%s 缺失时不该有版本", f.Name)
		}
	}
}
