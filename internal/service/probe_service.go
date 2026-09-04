package service

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

type ProbeResult struct {
	IsOnline        bool
	IsCaptivePortal bool
	RedirectURL     string
	Latency         time.Duration
	Err             error
}

// FastProbeCaptivePortal checks whether genuine internet connectivity is available
// or if outbound HTTP requests are being intercepted by a campus BRAS Captive Portal.
func FastProbeCaptivePortal(ctx context.Context, localIP string) ProbeResult {
	start := time.Now()

	dialer := &net.Dialer{
		Timeout: 2 * time.Second,
	}
	if localIP != "" {
		if ip := net.ParseIP(localIP); ip != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}

	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		MaxIdleConns:        1,
		IdleConnTimeout:     2 * time.Second,
		TLSHandshakeTimeout: 2 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Do not follow redirects; an HTTP 302 directly indicates captive portal interception
			return http.ErrUseLastResponse
		},
	}

	// Use lightweight 204 endpoint
	probeURL := "http://connectivitycheck.gstatic.com/generate_204"
	req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
	if err != nil {
		return ProbeResult{Err: err}
	}

	resp, err := client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return ProbeResult{Latency: latency, Err: err}
	}
	defer resp.Body.Close()

	// If BRAS intercepts HTTP and redirects (HTTP 301, 302, 307)
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusTemporaryRedirect {
		location := resp.Header.Get("Location")
		return ProbeResult{
			IsOnline:        false,
			IsCaptivePortal: true,
			RedirectURL:     location,
			Latency:         latency,
		}
	}

	if resp.StatusCode == http.StatusNoContent || (resp.StatusCode == http.StatusOK && resp.ContentLength == 0) {
		return ProbeResult{
			IsOnline: true,
			Latency:  latency,
		}
	}

	return ProbeResult{
		IsOnline: true,
		Latency:  latency,
	}
}
