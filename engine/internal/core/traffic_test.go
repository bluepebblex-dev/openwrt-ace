package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
)

func apiPortOf(t *testing.T, rawURL string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("test server port: %v", err)
	}
	return port
}

// Current cores put the running totals in the same /traffic object as the
// rate. Reading them from there means one request per tick instead of two, so
// the fallback must not be hit at all in that case.
func TestTrafficSampleReadsTotalsFromTraffic(t *testing.T) {
	var connectionsHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/traffic":
			fmt.Fprint(w, `{"up":10,"down":20,"upTotal":300,"downTotal":400}`)
		case "/connections":
			atomic.AddInt32(&connectionsHits, 1)
			fmt.Fprint(w, `{"downloadTotal":1,"uploadTotal":2,"connections":null}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s, err := TrafficSampleNow(apiPortOf(t, srv.URL))
	if err != nil {
		t.Fatalf("TrafficSampleNow: %v", err)
	}
	if s.UpBps != 10 || s.DownBps != 20 {
		t.Errorf("rate = %d/%d, want 10/20", s.UpBps, s.DownBps)
	}
	if s.UpTotal != 300 || s.DownTotal != 400 {
		t.Errorf("totals = %d/%d, want 300/400", s.UpTotal, s.DownTotal)
	}
	if n := atomic.LoadInt32(&connectionsHits); n != 0 {
		t.Errorf("/connections hit %d times, want 0 when totals are inline", n)
	}
}

// Cores that predate the inline totals must still yield a usable sample: the
// rate is what the card shows, and the totals come from /connections.
func TestTrafficSampleFallsBackToConnections(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/traffic":
			fmt.Fprint(w, `{"up":5,"down":6}`)
		case "/connections":
			fmt.Fprint(w, `{"downloadTotal":9000,"uploadTotal":7000,"connections":null}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s, err := TrafficSampleNow(apiPortOf(t, srv.URL))
	if err != nil {
		t.Fatalf("TrafficSampleNow: %v", err)
	}
	if s.UpBps != 5 || s.DownBps != 6 {
		t.Errorf("rate = %d/%d, want 5/6", s.UpBps, s.DownBps)
	}
	if s.UpTotal != 7000 || s.DownTotal != 9000 {
		t.Errorf("totals = %d/%d, want 7000/9000 from /connections", s.UpTotal, s.DownTotal)
	}
}

// A core that rejects /traffic must surface the error rather than a silent
// zero sample: the UI relies on the failure to keep the previous reading.
func TestTrafficSampleReportsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := TrafficSampleNow(apiPortOf(t, srv.URL)); err == nil {
		t.Fatal("expected an error for a 404 /traffic")
	}
}

// The old wrapper must keep its two-value contract for the Windows GUI.
func TestTrafficWrapperKeepsSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"up":11,"down":22,"upTotal":1,"downTotal":2}`)
	}))
	defer srv.Close()

	up, down, err := Traffic(apiPortOf(t, srv.URL))
	if err != nil {
		t.Fatalf("Traffic: %v", err)
	}
	if up != 11 || down != 22 {
		t.Fatalf("Traffic = %d/%d, want 11/22", up, down)
	}
}
