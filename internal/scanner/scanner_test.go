package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urlvnashezna/cipherwall/internal/config"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	return dir
}

func TestDetectsAWSKey(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"config/settings.yaml": "aws_access_key_id: AKIAIOSFODNN7EXAMPLE
",
	})
	cfg := config.Default()
	sc, err := New(cfg)
	require.NoError(t, err)
	fs, err := sc.ScanSecrets(dir)
	require.NoError(t, err)
	assert.Len(t, fs, 1, "should find one AWS key")
	assert.Equal(t, "aws_access_key", fs[0].RuleID)
	assert.Equal(t, 1, fs[0].Line)
}

func TestDetectsGitHubToken(t *testing.T) {
	dir := writeTree(t, map[string]string{
		".env": "GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEFG123456
",
	})
	cfg := config.Default()
	sc, _ := New(cfg)
	fs, err := sc.ScanSecrets(dir)
	require.NoError(t, err)
	require.Len(t, fs, 1)
	assert.Equal(t, "github_token", fs[0].RuleID)
}

func TestSkipsNodeModules(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"node_modules/pkg/index.js": "x = 'AKIAIOSFODNN7EXAMPLE'
",
		"app.js":                    "ok
",
	})
	cfg := config.Default()
	sc, _ := New(cfg)
	fs, err := sc.ScanSecrets(dir)
	require.NoError(t, err)
	assert.Len(t, fs, 0, "node_modules must be excluded")
}

func TestEntropyDetection(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"config.yaml": "token: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
",
	})
	cfg := config.Default()
	sc, _ := New(cfg)
	fs, err := sc.ScanSecrets(dir)
	require.NoError(t, err)
	assert.Len(t, fs, 1, "high-entropy token should be flagged")
}

func TestMaskSecret(t *testing.T) {
	assert.Equal(t, "abcd....wxyz", maskSecret("abcdefghijklmnopqrstuvwxyz"))
	assert.Equal(t, "****", maskSecret("short"))
}

func TestVersionCompare(t *testing.T) {
	assert.True(t, versionLess("v1.9.0", "v1.9.1"))
	assert.False(t, versionLess("v1.9.1", "v1.9.1"))
	assert.False(t, versionLess("v1.10.0", "v1.9.1"))
}
