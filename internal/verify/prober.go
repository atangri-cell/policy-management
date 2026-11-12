// Package verify performs the external reachability check that makes a DENY
// trustworthy: the controller never reports an unenforced DENY as success.
//
// "The orchestrator provisioned a VIP" is not the same as "it is reachable" —
// NAT and the gateway sit in front — so enforcement is confirmed from outside,
// against the endpoint's public hostname, exactly as the PoC did with its probe.
package verify

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"
)

// Result is the outcome of one external probe.
type Result struct {
	Reachable bool
	Code      int
	Latency   time.Duration
}

// Prober checks an endpoint's public hostname from outside the cluster.
type Prober struct {
	client *http.Client
}

func NewProber(insecureTLS bool) *Prober {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS}, //nolint:gosec // Bridge endpoints are self-signed
	}
	return &Prober{client: &http.Client{Transport: tr}}
}

// Probe issues a single GET https://host/path and reports whether it responded.
func (p *Prober) Probe(ctx context.Context, host, path string, timeout time.Duration) Result {
	if path == "" {
		path = "/"
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return Result{}
	}
	start := time.Now()
	resp, err := p.client.Do(req)
	lat := time.Since(start)
	if err != nil {
		return Result{Reachable: false, Latency: lat}
	}
	defer resp.Body.Close()
	// Any HTTP response at all means the public door is open (2xx/3xx/4xx/5xx).
	return Result{Reachable: true, Code: resp.StatusCode, Latency: lat}
}
