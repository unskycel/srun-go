package ui

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
)

//go:embed web/* web/icons/*
var WebFS embed.FS

// GetFS returns a sub-filesystem rooted at the embedded "web" folder.
func GetFS() (fs.FS, error) {
	sub, err := fs.Sub(WebFS, "web")
	if err != nil {
		return nil, fmt.Errorf("failed to sub embed.FS: %w", err)
	}
	return sub, nil
}

// MustGetFS returns a sub-filesystem rooted at "web" or panics on error.
func MustGetFS() fs.FS {
	sub, err := GetFS()
	if err != nil {
		panic(err)
	}
	return sub
}

// GetHTTPFileSystem returns an http.FileSystem rooted at the embedded "web" folder.
func GetHTTPFileSystem() (http.FileSystem, error) {
	sub, err := GetFS()
	if err != nil {
		return nil, err
	}
	return http.FS(sub), nil
}

// GetAsset reads a specific embedded asset file from the web folder.
func GetAsset(name string) ([]byte, error) {
	sub, err := GetFS()
	if err != nil {
		return nil, err
	}
	return fs.ReadFile(sub, name)
}
