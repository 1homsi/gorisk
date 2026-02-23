package php

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseComposerLock fuzzes the composer.lock parser.
// Must not panic on any input.
func FuzzParseComposerLock(f *testing.F) {
	f.Add([]byte(`{"packages":[],"packages-dev":[]}`))
	f.Add([]byte(`{"packages":[{"name":"monolog/monolog","version":"3.5.0","require":{"php":">=8.1"}}],"packages-dev":[]}`))
	f.Add([]byte(""))
	f.Add([]byte("not json"))
	f.Add([]byte(`{"packages":[{"name":"a/b","version":"1.0","require":{"c/d":"^2.0","php":"^8","ext-json":"*"}}],"packages-dev":[]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "composer.lock"), data, 0o600); err != nil {
			return
		}
		Load(dir) //nolint:errcheck
	})
}
