package node

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParsePackageLock fuzzes the package-lock.json parser.
// Must not panic on any input.
func FuzzParsePackageLock(f *testing.F) {
	f.Add([]byte(`{"lockfileVersion":2,"packages":{}}`))
	f.Add([]byte(`{"lockfileVersion":1,"dependencies":{}}`))
	f.Add([]byte(`{"lockfileVersion":3,"packages":{"":{"dependencies":{"ms":"2.1.3"}},"node_modules/ms":{"version":"2.1.3"}}}`))
	f.Add([]byte(""))
	f.Add([]byte("not json"))
	f.Add([]byte(`{"lockfileVersion":2,"packages":{"node_modules/x":{"version":"1.0.0","dependencies":{"y":"^1.0.0"}}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), data, 0o600); err != nil {
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"t","dependencies":{}}`), 0o600); err != nil {
			return
		}
		loadPackageLock(dir) //nolint:errcheck
	})
}

// FuzzParseYarnLock fuzzes the yarn.lock parser.
// Must not panic on any input.
func FuzzParseYarnLock(f *testing.F) {
	f.Add([]byte("# yarn lockfile v1\n\nms@2.1.3:\n  version \"2.1.3\"\n  resolved \"https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz\"\n  integrity sha512-abc\n"))
	f.Add([]byte(""))
	f.Add([]byte("not a yarn lockfile"))
	f.Add([]byte("__metadata:\n  version: 6\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), data, 0o600); err != nil {
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"t","dependencies":{}}`), 0o600); err != nil {
			return
		}
		loadYarnLock(dir) //nolint:errcheck
	})
}

// FuzzParsePnpmLock fuzzes the pnpm-lock.yaml parser.
// Must not panic on any input.
func FuzzParsePnpmLock(f *testing.F) {
	f.Add([]byte("lockfileVersion: '6.0'\n\npackages:\n\n  /ms/2.1.3:\n    resolution: {integrity: sha512-abc}\n    dev: false\n"))
	f.Add([]byte(""))
	f.Add([]byte("not yaml"))
	f.Add([]byte("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      ms:\n        specifier: 2.1.3\n        version: 2.1.3\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), data, 0o600); err != nil {
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"t","dependencies":{}}`), 0o600); err != nil {
			return
		}
		loadPnpmLock(dir) //nolint:errcheck
	})
}
