package main

import (
	"os"
	"path/filepath"
	"testing"
)

func setupCertDir(t *testing.T, domain string) string {
	t.Helper()
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatalf("failed to create cert dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "cert.pem"), []byte("cert"), 0644); err != nil {
		t.Fatalf("failed to write cert.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "privkey.pem"), []byte("key"), 0644); err != nil {
		t.Fatalf("failed to write privkey.pem: %v", err)
	}
	return tmpDir
}

func configForDir(tmpDir string) {
	config.Ssl.Certificate = filepath.Join(tmpDir, "$(SNI_SERVER_NAME)", "cert.pem")
	config.Ssl.Key = filepath.Join(tmpDir, "$(SNI_SERVER_NAME)", "privkey.pem")
}

// TestCertPathsForSNI_exact checks that a non-www SNI name resolves to the direct path.
func TestCertPathsForSNI_exact(t *testing.T) {
	tmpDir := setupCertDir(t, "some-domain.com")
	configForDir(tmpDir)

	certPath, keyPath := certPathsForSNI("some-domain.com")

	if certPath != filepath.Join(tmpDir, "some-domain.com", "cert.pem") {
		t.Errorf("unexpected certPath: %s", certPath)
	}
	if keyPath != filepath.Join(tmpDir, "some-domain.com", "privkey.pem") {
		t.Errorf("unexpected keyPath: %s", keyPath)
	}
}

// TestCertPathsForSNI_wwwWithOwnCert checks that www.some-domain.com resolves to its own cert when it exists.
func TestCertPathsForSNI_wwwWithOwnCert(t *testing.T) {
	tmpDir := setupCertDir(t, "www.some-domain.com")
	configForDir(tmpDir)

	certPath, keyPath := certPathsForSNI("www.some-domain.com")

	if certPath != filepath.Join(tmpDir, "www.some-domain.com", "cert.pem") {
		t.Errorf("unexpected certPath: %s", certPath)
	}
	if keyPath != filepath.Join(tmpDir, "www.some-domain.com", "privkey.pem") {
		t.Errorf("unexpected keyPath: %s", keyPath)
	}
}

// TestCertPathsForSNI_wwwFallback checks that www.some-domain.com falls back to some-domain.com
// when no cert exists for the www. variant.
func TestCertPathsForSNI_wwwFallback(t *testing.T) {
	tmpDir := setupCertDir(t, "some-domain.com")
	configForDir(tmpDir)

	certPath, keyPath := certPathsForSNI("www.some-domain.com")

	if certPath != filepath.Join(tmpDir, "some-domain.com", "cert.pem") {
		t.Errorf("unexpected certPath: %s", certPath)
	}
	if keyPath != filepath.Join(tmpDir, "some-domain.com", "privkey.pem") {
		t.Errorf("unexpected keyPath: %s", keyPath)
	}
}
