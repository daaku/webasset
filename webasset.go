// Package webasset manages static frontend assets.
//
// It provides the HTTP handler for serving assets and functionality to generate
// hashed asset URLs. Hashed URLs allow for caching the URL and marking them as
// immutable resources that the browser can cache indefinitely.
package webasset

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

// Library provides access to hashed asset URLs and is a http.Handler
// to serve them. This component is safe for concurrent use.
type Library struct {
	prefix        string
	dirs          []string
	cache         bool
	urlCache      sync.Map
	diskPathCache sync.Map
}

// NewLibrary creates a new Library to manage assets. The prefix is
// added to generated URLs and stripped from URLs when serving
// assets. The dirs is a list of directories to serve assets from.
// The cache parameter enables or disables the internal caching. This should be
// enabled in production to avoid unnecessary rehashing of file contents.
func NewLibrary(prefix string, dirs []string, cache bool) *Library {
	return &Library{
		prefix: prefix,
		dirs:   dirs,
		cache:  cache,
	}
}

var errFileNotFound = errors.New("webasset: file not found")

// DiskPath returns the path on disk for the given asset.
func (l *Library) DiskPath(asset string) (string, error) {
	if l.cache {
		fp, found := l.diskPathCache.Load(asset)
		if found {
			return fp.(string), nil
		}
	}

	for _, dir := range l.dirs {
		fp := filepath.Join(dir, asset)
		if _, err := os.Stat(fp); err == nil {
			if l.cache {
				l.diskPathCache.Store(asset, fp)
			}
			return fp, nil
		}
	}

	return "", errFileNotFound
}

// TryURL returns the hashed URL for the given asset.
func (l *Library) TryURL(asset string) (string, error) {
	// always work with clean paths
	asset = filepath.Clean(asset)

	if l.cache {
		u, found := l.urlCache.Load(asset)
		if found {
			return u.(string), nil
		}
	}

	fp, err := l.DiskPath(asset)
	if err != nil {
		if err == errFileNotFound {
			return "", errors.Errorf("webasset: asset not found: %q", asset)
		}
		return "", err
	}

	file, err := os.Open(fp)
	if err != nil {
		return "", errors.WithStack(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", errors.WithStack(err)
	}
	ext := filepath.Ext(asset)
	hashedURL := fmt.Sprintf(
		"%s%s.%x%s", l.prefix, asset[:len(asset)-len(ext)], h.Sum(nil)[:3], ext)
	if l.cache {
		l.urlCache.Store(asset, hashedURL)
	}
	return hashedURL, nil
}

// URL returns the hashed URL for the given asset. Unlike TryURL it
// panics on any errors. This provides an easier to use API, since it's usually
// safe to assume that assets exist and are under the developers control.
func (l *Library) URL(asset string) string {
	u, err := l.TryURL(asset)
	if err != nil {
		panic(err)
	}
	return u
}

func assetFromPath(p string) (string, error) {
	p = filepath.Clean(p)
	ext := filepath.Ext(p)
	if ext == "" {
		return "", errors.Errorf("webasset: extension missing in URL: %q", p)
	}

	rest := p[:len(p)-len(ext)]
	const lenHash = 6
	const lenDot = 1
	const minFilenameLen = 1
	if len(rest) < lenHash+lenDot+minFilenameLen {
		return "", errors.Errorf("webasset: invalid URL: %q", p)
	}

	asset := rest[:len(rest)-lenHash-lenDot] + ext
	return asset, nil
}

// ServeHTTP serves assets if it can. It returns a plain text 404 if the
// asset cannot be found.
func (l *Library) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	asset, err := assetFromPath(r.URL.Path)
	if err != nil {
		panic(err)
	}
	asset = strings.TrimPrefix(asset, l.prefix)

	fp, err := l.DiskPath(asset)
	if err != nil {
		if err == errFileNotFound {
			http.Error(w, "file not found", http.StatusNotFound)
		} else {
			http.Error(w, "unexpected internal error", http.StatusInternalServerError)
		}
		return
	}

	hashedURL, err := l.TryURL(asset)
	if err != nil {
		http.Error(w, "unexpected internal error", http.StatusInternalServerError)
		return
	}

	if r.URL.Path != hashedURL {
		http.Error(w, "incorrect URL for asset", http.StatusNotFound)
		return
	}

	w.Header().Set("Cache-Control", "public,max-age=31536000,immutable")
	http.ServeFile(w, r, fp)
}
