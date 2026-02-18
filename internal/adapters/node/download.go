package node

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// DownloadPackage fetches pkgName@version from the npm registry, extracts the
// tarball into a temp directory, and returns that directory path.
// The caller is responsible for removing the directory when done.
func DownloadPackage(pkgName, version string) (string, error) {
	// Resolve tarball URL via registry metadata.
	const registryBase = "https://registry.npmjs.org/"
	resp, err := http.Get(registryBase + pkgName + "/" + version) //nolint:noctx,gosec
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("npm registry returned %d for %s@%s", resp.StatusCode, pkgName, version)
	}

	var meta struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", err
	}
	if meta.Dist.Tarball == "" {
		return "", fmt.Errorf("no tarball URL in registry response for %s@%s", pkgName, version)
	}

	tarResp, err := http.Get(meta.Dist.Tarball) //nolint:noctx,gosec
	if err != nil {
		return "", err
	}
	defer tarResp.Body.Close()

	tmpDir, err := os.MkdirTemp("", "gorisk-npm-*")
	if err != nil {
		return "", err
	}

	if err := extractTarGz(tarResp.Body, tmpDir); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("extract tarball: %w", err)
	}

	// npm tarballs extract into a "package/" subdirectory.
	extracted := filepath.Join(tmpDir, "package")
	if _, err := os.Stat(extracted); err == nil {
		return extracted, nil
	}
	return tmpDir, nil
}

// extractTarGz extracts a .tar.gz stream into destDir.
func extractTarGz(r io.Reader, destDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Strip the leading "package/" prefix and sanitise to prevent traversal.
		parts := strings.SplitN(filepath.ToSlash(hdr.Name), "/", 2)
		if len(parts) < 2 {
			continue
		}
		rel := filepath.Clean(parts[1])
		if strings.HasPrefix(rel, "..") {
			continue
		}

		dest := filepath.Join(destDir, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0750); err != nil {
			return err
		}
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, tr) //nolint:gosec
		f.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}
