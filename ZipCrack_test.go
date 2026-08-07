package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUniqueCharset(t *testing.T) {
	got := uniqueCharset("aabcc123a")
	want := "abc123"
	if got != want {
		t.Fatalf("uniqueCharset = %q, want %q", got, want)
	}
}

func TestBruteforceTotal(t *testing.T) {
	// charset 2, lengths 1-3: 2 + 4 + 8 = 14
	if n := bruteforceTotal(2, 1, 3); n != 14 {
		t.Fatalf("bruteforceTotal(2,1,3) = %d, want 14", n)
	}
	if n := bruteforceTotal(10, 2, 2); n != 100 {
		t.Fatalf("bruteforceTotal(10,2,2) = %d, want 100", n)
	}
	if n := bruteforceTotal(0, 1, 3); n != 0 {
		t.Fatalf("empty charset should yield 0")
	}
}

func TestFormatCount(t *testing.T) {
	cases := map[uint64]string{
		0:           "0",
		999:         "999",
		1000:        "1.00K",
		1_500_000:   "1.50M",
		2_000_000_000: "2.00B",
	}
	for n, want := range cases {
		if got := formatCount(n); got != want {
			t.Errorf("formatCount(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestZipCryptoCheckAndCrack(t *testing.T) {
	zipPath := buildFixture(t, "zipcrypto", false, "secret")
	target, err := loadCrackTarget(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if target.kind != encZipCrypto {
		t.Fatalf("kind = %v, want ZipCrypto", target.kind)
	}
	if !target.tryPassword("secret") {
		t.Fatal("expected password 'secret' to succeed")
	}
	if target.tryPassword("wrong") {
		t.Fatal("expected password 'wrong' to fail")
	}
}

func TestAESCheckAndCrack(t *testing.T) {
	if _, err := exec.LookPath("7z"); err != nil {
		t.Skip("7z not available")
	}
	zipPath := buildFixture(t, "aes", true, "secret")
	target, err := loadCrackTarget(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if target.kind != encAES {
		t.Fatalf("kind = %v, want AES", target.kind)
	}
	if !target.tryPassword("secret") {
		t.Fatal("expected password 'secret' to succeed")
	}
	if target.tryPassword("wrong") {
		t.Fatal("expected password 'wrong' to fail")
	}
}

func TestLoadRejectsUnencrypted(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(plain, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(dir, "plain.zip")
	cmd := exec.Command("zip", "-q", zipPath, filepath.Base(plain))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zip: %v (%s)", err, out)
	}
	if _, err := loadCrackTarget(zipPath); err == nil {
		t.Fatal("expected error for unencrypted zip")
	}
}

// buildFixture creates a small encrypted zip using system tools.
func buildFixture(t *testing.T, name string, aes bool, password string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(src, []byte("hello zipcrack\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(dir, name+".zip")
	var cmd *exec.Cmd
	if aes {
		cmd = exec.Command("7z", "a", "-p"+password, "-mem=AES256", zipPath, src)
	} else {
		cmd = exec.Command("zip", "-P", password, name+".zip", "note.txt")
		cmd.Dir = dir
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create fixture: %v (%s)", err, out)
	}
	return zipPath
}

func TestStatsFirstWriterWins(t *testing.T) {
	s := &Stats{}
	s.SetFound("one")
	s.SetFound("two")
	if got := s.GetPassword(); got != "one" {
		t.Fatalf("GetPassword = %q, want %q", got, "one")
	}
	if !s.IsFound() {
		t.Fatal("expected found")
	}
}

func init() {
	// Keep tests from being starved on tiny CI boxes.
	runtime.GOMAXPROCS(runtime.NumCPU())
}
