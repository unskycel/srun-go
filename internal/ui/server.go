package ui

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var customMIMETypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".htm":   "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".js":    "application/javascript; charset=utf-8",
	".mjs":   "application/javascript; charset=utf-8",
	".json":  "application/json; charset=utf-8",
	".ttf":   "font/ttf",
	".otf":   "font/otf",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".ico":   "image/x-icon",
	".svg":   "image/svg+xml",
	".gif":   "image/gif",
}

func init() {
	for ext, typ := range customMIMETypes {
		_ = mime.AddExtensionType(ext, typ)
	}
}

// AssetServer serves embedded web frontend assets over local HTTP loopback.
type AssetServer struct {
	listener net.Listener
	server   *http.Server
	port     int
	url      string
	mu       sync.Mutex
	closed   bool
}

// NewAssetHandler returns an http.Handler that serves embedded UI assets with proper MIME types.
func NewAssetHandler(fsys http.FileSystem) http.Handler {
	fileServer := http.FileServer(fsys)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD")

		ext := strings.ToLower(filepath.Ext(r.URL.Path))
		if cType, ok := customMIMETypes[ext]; ok {
			w.Header().Set("Content-Type", cType)
		}

		fileServer.ServeHTTP(w, r)
	})
}

// StartAssetServer launches the local HTTP loopback server on an ephemeral port.
func StartAssetServer() (*AssetServer, error) {
	fsys, err := GetHTTPFileSystem()
	if err != nil {
		return nil, fmt.Errorf("failed to get embedded filesystem: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind loopback listener: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	handler := NewAssetHandler(fsys)

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	assetServer := &AssetServer{
		listener: listener,
		server:   srv,
		port:     port,
		url:      fmt.Sprintf("http://127.0.0.1:%d/index.html", port),
	}

	go func() {
		_ = srv.Serve(listener)
	}()

	return assetServer, nil
}

// URL returns the full HTTP URL pointing to the embedded index.html.
func (s *AssetServer) URL() string {
	return s.url
}

// Port returns the bound local TCP port.
func (s *AssetServer) Port() int {
	return s.port
}

// Close gracefully shuts down the asset HTTP server.
func (s *AssetServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}
