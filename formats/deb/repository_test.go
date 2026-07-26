package deb

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestRepositoryPackagesCompressedAndBounded(t *testing.T) {
	content := []byte("Package: demo\nVersion: 1.2.3-1\nArchitecture: amd64\nFilename: pool/demo.deb\nSize: 7\nSHA256: " + strings.Repeat("a", 64) + "\nDescription: demo\n continuation\n\n")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecompressRepositoryPackages("Packages.gz", compressed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	packages, err := ParseRepositoryPackages(decoded)
	if err != nil || len(packages) != 1 || packages[0].Package != "demo" {
		t.Fatalf("packages=%#v err=%v", packages, err)
	}
}

func TestRepositoryPackagesRejectsEncodedTraversal(t *testing.T) {
	content := []byte("Package: demo\nVersion: 1\nArchitecture: all\nFilename: %2e%2e/secret.deb\nSize: 1\nSHA256: " + strings.Repeat("a", 64) + "\n")
	if _, err := ParseRepositoryPackages(content); err == nil {
		t.Fatal("encoded traversal path was accepted")
	}
}
