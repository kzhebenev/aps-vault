package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fake machine API: one secret, counts hits, can be switched to failing.
func fakeVault(t *testing.T, failing *atomic.Bool, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer vlt_test_token" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "invalid token"})
			return
		}
		if failing.Load() {
			w.WriteHeader(503)
			return
		}
		hits.Add(1)
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/m/secret/db-password":
			_ = json.NewEncoder(w).Encode(Secret{Name: "db-password", Value: "s3cr3t", Login: "app", UpdatedAt: "2026-10-02T00:00:00"})
		case r.Method == "POST" && r.URL.Path == "/api/v1/m/secret/new":
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["value"] != "v" || b["login"] != "u" {
				t.Errorf("bad put body: %v", b)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "name": "new", "created": true})
		case r.Method == "GET" && r.URL.Path == "/api/v1/m/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "scope_folder": "f"})
		default:
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "not found"})
		}
	}))
}

func TestRejectsNonServiceToken(t *testing.T) {
	if _, err := New("http://x", "my master password"); err == nil {
		t.Fatal("master password must be rejected")
	}
}

func TestGetCachesAndFailsOpen(t *testing.T) {
	var failing atomic.Bool
	var hits atomic.Int32
	srv := fakeVault(t, &failing, &hits)
	defer srv.Close()
	c, err := New(srv.URL, "vlt_test_token", Options{MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v, err := c.Get(ctx, "db-password")
	if err != nil || v != "s3cr3t" {
		t.Fatalf("get: %v %q", err, v)
	}
	if _, err := c.Get(ctx, "db-password"); err != nil || hits.Load() != 1 {
		t.Fatalf("second get must be served from cache, hits=%d", hits.Load())
	}
	// vault down + cache expired → stale value is still returned (fail-open)
	c.ttl = time.Nanosecond
	time.Sleep(time.Millisecond)
	failing.Store(true)
	if v, err := c.Get(ctx, "db-password"); err != nil || v != "s3cr3t" {
		t.Fatalf("fail-open: %v %q", err, v)
	}
	// but an unknown name with the vault down is an error
	if _, err := c.Get(ctx, "never-seen"); err == nil {
		t.Fatal("expected error for uncached secret while vault is down")
	}
}

func TestNotFoundIsNotRetriedAndCarriesStatus(t *testing.T) {
	var failing atomic.Bool
	var hits atomic.Int32
	srv := fakeVault(t, &failing, &hits)
	defer srv.Close()
	c, _ := New(srv.URL, "vlt_test_token")
	_, err := c.Get(context.Background(), "missing")
	var he *Error
	if !errors.As(err, &he) || he.Status != 404 {
		t.Fatalf("want 404 Error, got %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("404 must not be retried, hits=%d", hits.Load())
	}
}

func TestPutAndHealth(t *testing.T) {
	var failing atomic.Bool
	var hits atomic.Int32
	srv := fakeVault(t, &failing, &hits)
	defer srv.Close()
	c, _ := New(srv.URL, "vlt_test_token")
	if err := c.Put(context.Background(), "new", "v", "u", "", ""); err != nil {
		t.Fatal(err)
	}
	h, err := c.Health(context.Background())
	if err != nil || h["status"] != "ok" {
		t.Fatalf("health: %v %v", err, h)
	}
}

func TestBadTokenIs401(t *testing.T) {
	var failing atomic.Bool
	var hits atomic.Int32
	srv := fakeVault(t, &failing, &hits)
	defer srv.Close()
	c, _ := New(srv.URL, "vlt_wrong")
	_, err := c.Get(context.Background(), "db-password")
	var he *Error
	if !errors.As(err, &he) || he.Status != 401 {
		t.Fatalf("want 401, got %v", err)
	}
}
