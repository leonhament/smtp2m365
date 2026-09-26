package report

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecentWrapsAndOrdersNewestFirst(t *testing.T) {
	r := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 3)
	for _, id := range []string{"a", "b", "c", "d"} {
		r.Record(Event{ID: id, Outcome: Delivered})
	}
	got := r.Recent(10)
	if len(got) != 3 || got[0].ID != "d" || got[2].ID != "b" {
		t.Fatalf("Recent = %+v", got)
	}
	if r.Stats().Counts[Delivered] != 4 {
		t.Errorf("count = %d, want 4", r.Stats().Counts[Delivered])
	}
}

func TestHandlerRequiresToken(t *testing.T) {
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 10).Handler("secret")
	for path, want := range map[string]int{"/healthz": 200, "/api/stats": 401} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("%s without token: %d, want %d", path, rec.Code, want)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("/api/events with token: %d", rec.Code)
	}
}
