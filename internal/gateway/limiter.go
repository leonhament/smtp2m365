package gateway

import (
	"net/netip"
	"sync"
	"time"
)

// failureLimiter temporarily refuses client IPs after repeated
// authentication failures.
type failureLimiter struct {
	max    int
	window time.Duration

	mu sync.Mutex
	m  map[netip.Addr]*failures
}

type failures struct {
	n     int
	since time.Time
}

func newFailureLimiter(max int, window time.Duration) *failureLimiter {
	return &failureLimiter{max: max, window: window, m: map[netip.Addr]*failures{}}
}

func (l *failureLimiter) Blocked(ip netip.Addr) bool {
	if l.max <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.m[ip]
	if f == nil {
		return false
	}
	if time.Since(f.since) > l.window {
		delete(l.m, ip)
		return false
	}
	return f.n >= l.max
}

func (l *failureLimiter) Fail(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.m) > 10000 {
		for k, f := range l.m {
			if now.Sub(f.since) > l.window {
				delete(l.m, k)
			}
		}
	}
	f := l.m[ip]
	if f == nil || now.Sub(f.since) > l.window {
		f = &failures{since: now}
		l.m[ip] = f
	}
	f.n++
}

func (l *failureLimiter) Reset(ip netip.Addr) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}
