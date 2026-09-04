package srun

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

const (
	DefaultDialTimeout   = 3 * time.Second
	DefaultKeepAlive     = 30 * time.Second
	DefaultClientTimeout = 10 * time.Second
)

// IsValidUnicastIPv4 checks if an IP is a valid usable unicast IPv4 (non-loopback, non-multicast, non-linklocal).
func IsValidUnicastIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4.IsLoopback() || ip4.IsMulticast() || ip4.IsUnspecified() {
		return false
	}
	if ip4[0] == 169 && ip4[1] == 254 {
		return false
	}
	if ip4[0] == 0 {
		return false
	}
	return true
}

// EnumerateIPv4Addresses returns all active unicast IPv4 network interfaces on the local system.
func EnumerateIPv4Addresses() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate network interfaces: %w", err)
	}

	var results []InterfaceInfo
	seen := make(map[string]bool)

	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip4 := ipnet.IP.To4()
			if ip4 != nil && IsValidUnicastIPv4(ip4) {
				ipStr := ip4.String()
				if !seen[ipStr] {
					seen[ipStr] = true
					results = append(results, InterfaceInfo{
						InterfaceName: ifi.Name,
						IP:            ipStr,
						MAC:           ifi.HardwareAddr.String(),
						IsUp:          true,
						IsLoopback:    false,
					})
				}
			}
		}
	}

	return results, nil
}

// GetLocalIPv4List returns a string slice of all available local unicast IPv4 addresses.
func GetLocalIPv4List() ([]string, error) {
	ifaces, err := EnumerateIPv4Addresses()
	if err != nil {
		return nil, err
	}
	list := make([]string, len(ifaces))
	for i, ifi := range ifaces {
		list[i] = ifi.IP
	}
	return list, nil
}

// NewCustomDialer constructs a net.Dialer bound to the specified local IPv4 address.
func NewCustomDialer(localIP string, timeout time.Duration) *net.Dialer {
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: DefaultKeepAlive,
	}

	cleanIP := strings.TrimSpace(localIP)
	if cleanIP != "" && !strings.EqualFold(cleanIP, "auto") && !strings.EqualFold(cleanIP, "default") {
		parsedIP := net.ParseIP(cleanIP)
		if parsedIP != nil {
			dialer.LocalAddr = &net.TCPAddr{
				IP:   parsedIP,
				Port: 0,
			}
		}
	}

	return dialer
}

// NewCustomTransport constructs an http.Transport configured with the custom dialer and TLS settings.
func NewCustomTransport(localIP string, timeout time.Duration, insecureTLS bool) *http.Transport {
	dialer := NewCustomDialer(localIP, timeout)

	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   DefaultDialTimeout,
		ResponseHeaderTimeout: DefaultDialTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecureTLS,
		},
	}
}

// NewHTTPClient creates an http.Client with source IP socket binding.
func NewHTTPClient(localIP string, timeout time.Duration, insecureTLS bool) *http.Client {
	if timeout <= 0 {
		timeout = DefaultClientTimeout
	}

	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Transport: NewCustomTransport(localIP, timeout, insecureTLS),
		Timeout:   timeout,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// ProbeGatewayInterfaces tests connectivity to the SRun gateway across all local network interfaces.
func ProbeGatewayInterfaces(ctx context.Context, gatewayHost string, timeout time.Duration) (*GatewayProbeSummary, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	ifaces, err := EnumerateIPv4Addresses()
	if err != nil {
		return nil, err
	}

	type probeCandidate struct {
		IP            string
		Label         string
		InterfaceName string
	}

	candidates := []probeCandidate{
		{
			IP:            "",
			Label:         "默认路由",
			InterfaceName: "OS Routing",
		},
	}

	for _, ifi := range ifaces {
		candidates = append(candidates, probeCandidate{
			IP:            ifi.IP,
			Label:         fmt.Sprintf("%s (%s)", ifi.InterfaceName, ifi.IP),
			InterfaceName: ifi.InterfaceName,
		})
	}

	results := make([]InterfaceProbeResult, len(candidates))
	var wg sync.WaitGroup

	for i, c := range candidates {
		wg.Add(1)
		go func(idx int, cand probeCandidate) {
			defer wg.Done()

			client := NewHTTPClient(cand.IP, timeout, true)
			testURL := fmt.Sprintf("http://%s/cgi-bin/rad_user_info?callback=JQuery", gatewayHost)

			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				results[idx] = InterfaceProbeResult{
					IP:            cand.IP,
					Label:         cand.Label,
					InterfaceName: cand.InterfaceName,
					Reachable:     false,
					StatusMessage: err.Error(),
				}
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				// Retry with https
				httpsURL := fmt.Sprintf("https://%s/cgi-bin/rad_user_info?callback=JQuery", gatewayHost)
				reqHttps, hErr := http.NewRequestWithContext(ctx, "GET", httpsURL, nil)
				if hErr == nil {
					respHttps, doErr := client.Do(reqHttps)
					if doErr == nil {
						_ = respHttps.Body.Close()
						results[idx] = InterfaceProbeResult{
							IP:            cand.IP,
							Label:         cand.Label,
							InterfaceName: cand.InterfaceName,
							Reachable:     true,
							StatusMessage: "OK (HTTPS)",
						}
						return
					}
				}

				results[idx] = InterfaceProbeResult{
					IP:            cand.IP,
					Label:         cand.Label,
					InterfaceName: cand.InterfaceName,
					Reachable:     false,
					StatusMessage: "无法连接网关",
				}
				return
			}
			_ = resp.Body.Close()

			results[idx] = InterfaceProbeResult{
				IP:            cand.IP,
				Label:         cand.Label,
				InterfaceName: cand.InterfaceName,
				Reachable:     true,
				StatusMessage: "OK",
			}
		}(i, c)
	}

	wg.Wait()

	reachableCount := 0
	for _, r := range results {
		if r.Reachable {
			reachableCount++
		}
	}

	return &GatewayProbeSummary{
		Gateway:        gatewayHost,
		ReachableCount: reachableCount,
		Results:        results,
	}, nil
}
