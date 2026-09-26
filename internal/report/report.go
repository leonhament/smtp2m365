// Package report records one event per message (or rejected attempt) as
// structured JSON logs and keeps recent events and counters in memory for
// the admin API.
//
// In Azure the JSON log lines land in Log Analytics, which is the durable
// store for reporting; the in-memory view is a convenience.
package report

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Outcome string

const (
	Delivered Outcome = "delivered"
	Rejected  Outcome = "rejected" // refused by gateway policy
	Failed    Outcome = "failed"   // accepted by policy, refused or errored at Exchange Online
)

type Event struct {
	Time       time.Time `json:"time"`
	ID         string    `json:"id,omitempty"`
	RemoteIP   string    `json:"remote_ip"`
	Listener   string    `json:"listener"`
	User       string    `json:"user,omitempty"`
	From       string    `json:"from,omitempty"`
	HeaderFrom []string  `json:"header_from,omitempty"`
	Recipients []string  `json:"recipients,omitempty"`
	MessageID  string    `json:"message_id,omitempty"`
	Size       int       `json:"size,omitempty"`
	Stage      string    `json:"stage"`
	Outcome    Outcome   `json:"outcome"`
	Reason     string    `json:"reason,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
}

type Stats struct {
	Started time.Time         `json:"started"`
	Counts  map[Outcome]int64 `json:"counts"`
	// Connections dropped because the client IP is not allowed. Counted
	// only, since internet scanners would otherwise flood the event log.
	DroppedConnections int64 `json:"dropped_connections"`
}

type Recorder struct {
	log *slog.Logger

	mu      sync.Mutex
	ring    []Event
	next    int
	full    bool
	counts  map[Outcome]int64
	dropped int64
	started time.Time
}

func New(log *slog.Logger, size int) *Recorder {
	if size < 1 {
		size = 1
	}
	return &Recorder{log: log, ring: make([]Event, size), counts: map[Outcome]int64{}, started: time.Now()}
}

func (r *Recorder) Record(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	level := slog.LevelInfo
	if e.Outcome != Delivered {
		level = slog.LevelWarn
	}
	r.log.LogAttrs(context.Background(), level, "smtp event",
		slog.String("id", e.ID),
		slog.String("remote_ip", e.RemoteIP),
		slog.String("listener", e.Listener),
		slog.String("user", e.User),
		slog.String("from", e.From),
		slog.Any("header_from", e.HeaderFrom),
		slog.Any("recipients", e.Recipients),
		slog.String("message_id", e.MessageID),
		slog.Int("size", e.Size),
		slog.String("stage", e.Stage),
		slog.String("outcome", string(e.Outcome)),
		slog.String("reason", e.Reason),
		slog.Int64("duration_ms", e.DurationMS),
	)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[e.Outcome]++
	r.ring[r.next] = e
	r.next = (r.next + 1) % len(r.ring)
	if r.next == 0 {
		r.full = true
	}
}

func (r *Recorder) CountDropped() {
	r.mu.Lock()
	r.dropped++
	r.mu.Unlock()
}

// Recent returns up to n events, newest first.
func (r *Recorder) Recent(n int) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	size := r.next
	if r.full {
		size = len(r.ring)
	}
	if n <= 0 || n > size {
		n = size
	}
	out := make([]Event, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, r.ring[(r.next-i+len(r.ring))%len(r.ring)])
	}
	return out
}

func (r *Recorder) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	counts := make(map[Outcome]int64, len(r.counts))
	for k, v := range r.counts {
		counts[k] = v
	}
	return Stats{Started: r.started, Counts: counts, DroppedConnections: r.dropped}
}

// Handler serves /healthz, /api/stats and /api/events?limit=N.
func (r *Recorder) Handler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /api/stats", requireToken(token, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, r.Stats())
	}))
	mux.Handle("GET /api/events", requireToken(token, func(w http.ResponseWriter, req *http.Request) {
		limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 100
		}
		writeJSON(w, r.Recent(limit))
	}))
	return mux
}

func requireToken(token string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if token != "" {
			got, _ := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h(w, req)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
