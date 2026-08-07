package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yeka/zip"
	"golang.org/x/crypto/pbkdf2"
)

const (
	modeDictionary   = 0
	modeBruteforce   = 1
	version          = "3.0.0"
	progressInterval = 500 * time.Millisecond

	// Exit codes
	exitFound    = 0
	exitNotFound = 1
	exitError    = 2

	zipCryptoHeaderLen = 12
	winzipAESExtraID   = 0x9901
	maxUncompressed    = 64 << 20 // 64 MiB safety cap for a single entry
)

// Built-in charset fragments (hashcat-style).
const (
	charsetLower   = "abcdefghijklmnopqrstuvwxyz"
	charsetUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsetDigits  = "0123456789"
	charsetSpecial = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?\\"
)

// Config holds parsed CLI options.
type Config struct {
	ZipFile    string
	AttackMode int
	DictFile   string
	Charset    string
	MinLen     int
	MaxLen     int
	Workers    int
	Quiet      bool
}

// Stats tracks crack progress without heavy locking.
type Stats struct {
	tried    atomic.Uint64
	found    atomic.Bool
	password atomic.Value // string
}

func (s *Stats) SetFound(pw string) {
	// First writer wins; later successes are ignored.
	if s.found.CompareAndSwap(false, true) {
		s.password.Store(pw)
	}
}

func (s *Stats) IsFound() bool { return s.found.Load() }

func (s *Stats) GetPassword() string {
	if v := s.password.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// ---------------------------------------------------------------------------
// Archive target — parsed once, verified entirely in memory
// ---------------------------------------------------------------------------

type encryptionKind int

const (
	encZipCrypto encryptionKind = iota
	encAES
)

// crackTarget is the single encrypted entry used for password checks.
type crackTarget struct {
	name             string
	kind             encryptionKind
	method           uint16 // actual compression method (Store/Deflate)
	flags            uint16
	crc32            uint32
	modTime          uint16
	uncompressedSize uint64
	// raw is the encrypted payload from the local file body.
	// ZipCrypto: 12-byte header + encrypted compressed bytes
	// AES: salt + 2-byte PV + encrypted compressed bytes + 10-byte authcode
	raw []byte
	// AES-only fields
	aesKeyLen int
	salt      []byte
	pwv       []byte // 2-byte password verification value
}

func loadCrackTarget(path string) (*crackTarget, error) {
	rc, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer rc.Close()

	var best *zip.File
	for _, f := range rc.File {
		if !f.IsEncrypted() || strings.HasSuffix(f.Name, "/") {
			continue
		}
		// Prefer the smallest encrypted payload — faster full verifies.
		if best == nil || f.CompressedSize64 < best.CompressedSize64 {
			best = f
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no encrypted files found in %s", path)
	}
	if best.CompressedSize64 == 0 {
		return nil, fmt.Errorf("encrypted entry %q has empty payload", best.Name)
	}

	offset, err := best.DataOffset()
	if err != nil {
		return nil, fmt.Errorf("data offset for %q: %w", best.Name, err)
	}

	// Read the encrypted body once. Done at startup, not per password.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, best.CompressedSize64)
	_, err = f.ReadAt(raw, offset)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("read encrypted payload: %w", err)
	}

	t := &crackTarget{
		name:             best.Name,
		method:           best.Method,
		flags:            best.Flags,
		crc32:            best.CRC32,
		modTime:          best.ModifiedTime,
		uncompressedSize: best.UncompressedSize64,
		raw:              raw,
	}

	if strength, method, ok := parseAESExtra(best.Extra); ok {
		t.kind = encAES
		t.method = method
		switch strength {
		case 1:
			t.aesKeyLen = 16
		case 2:
			t.aesKeyLen = 24
		case 3:
			t.aesKeyLen = 32
		default:
			return nil, fmt.Errorf("unsupported AES strength %d in %q", strength, best.Name)
		}
		saltLen := t.aesKeyLen / 2
		if len(raw) < saltLen+2+10 {
			return nil, fmt.Errorf("AES payload too short for %q", best.Name)
		}
		t.salt = raw[:saltLen]
		t.pwv = raw[saltLen : saltLen+2]
	} else {
		t.kind = encZipCrypto
		if len(raw) < zipCryptoHeaderLen {
			return nil, fmt.Errorf("ZipCrypto payload too short for %q", best.Name)
		}
	}

	return t, nil
}

func parseAESExtra(extra []byte) (strength byte, method uint16, ok bool) {
	for i := 0; i+4 <= len(extra); {
		id := binary.LittleEndian.Uint16(extra[i:])
		sz := int(binary.LittleEndian.Uint16(extra[i+2:]))
		i += 4
		if sz < 0 || i+sz > len(extra) {
			break
		}
		if id == winzipAESExtraID && sz >= 7 {
			// vendor version (2) + vendor id (2) + strength (1) + method (2)
			strength = extra[i+4]
			method = binary.LittleEndian.Uint16(extra[i+5:])
			return strength, method, true
		}
		i += sz
	}
	return 0, 0, false
}

// ---------------------------------------------------------------------------
// Password verification (in-memory, no zip reopen)
// ---------------------------------------------------------------------------

func (t *crackTarget) tryPassword(password string) bool {
	switch t.kind {
	case encAES:
		return t.tryAES(password)
	default:
		return t.tryZipCrypto(password)
	}
}

// tryAES checks the WinZip AES password verification value (PBKDF2),
// then confirms with HMAC-SHA1-80 over the ciphertext when PV matches.
func (t *crackTarget) tryAES(password string) bool {
	total := t.aesKeyLen*2 + 2
	key := pbkdf2.Key([]byte(password), t.salt, 1000, total, sha1.New)
	authKey := key[t.aesKeyLen : t.aesKeyLen*2]
	pwv := key[t.aesKeyLen*2:]
	if subtle.ConstantTimeCompare(pwv, t.pwv) != 1 {
		return false
	}
	// PV is only 2 bytes — verify the auth code to eliminate false positives.
	saltLen := len(t.salt)
	encData := t.raw[saltLen+2 : len(t.raw)-10]
	authcode := t.raw[len(t.raw)-10:]
	mac := hmac.New(sha1.New, authKey)
	_, _ = mac.Write(encData)
	expected := mac.Sum(nil)[:10]
	return subtle.ConstantTimeCompare(expected, authcode) == 1
}

// tryZipCrypto uses the 12-byte encryption header as a cheap filter, then
// fully decrypts + inflates + CRC-checks only on candidates that pass.
func (t *crackTarget) tryZipCrypto(password string) bool {
	pass := []byte(password)

	// Cheap 12-byte header check (rejects ~255/256 wrong passwords).
	var z zipCryptoState
	z.init(pass)
	var last byte
	for i := 0; i < zipCryptoHeaderLen; i++ {
		last = z.decryptByte(t.raw[i])
	}
	if last != t.zipCryptoCheckByte() {
		return false
	}

	// Full decrypt of remaining payload.
	plain := make([]byte, len(t.raw)-zipCryptoHeaderLen)
	for i := range plain {
		plain[i] = z.decryptByte(t.raw[zipCryptoHeaderLen+i])
	}

	decoded, err := decompress(t.method, plain, t.uncompressedSize)
	if err != nil {
		return false
	}
	if t.uncompressedSize != 0 && uint64(len(decoded)) != t.uncompressedSize {
		return false
	}
	return crc32.ChecksumIEEE(decoded) == t.crc32
}

func (t *crackTarget) zipCryptoCheckByte() byte {
	// When the data descriptor flag (bit 3) is set, the check byte is the
	// high byte of the DOS modification time; otherwise the high byte of CRC32.
	if t.flags&0x8 != 0 {
		return byte(t.modTime >> 8)
	}
	return byte(t.crc32 >> 24)
}

func decompress(method uint16, data []byte, expectedSize uint64) ([]byte, error) {
	switch method {
	case zip.Store:
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	case zip.Deflate:
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		limit := expectedSize
		if limit == 0 || limit > maxUncompressed {
			limit = maxUncompressed
		}
		var buf bytes.Buffer
		if expectedSize > 0 && expectedSize <= maxUncompressed {
			buf.Grow(int(expectedSize))
		}
		n, err := io.Copy(&buf, io.LimitReader(fr, int64(limit)+1))
		if err != nil {
			return nil, err
		}
		if uint64(n) > limit {
			return nil, fmt.Errorf("uncompressed data exceeds limit")
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported compression method %d", method)
	}
}

// zipCryptoState implements PKZIP traditional encryption.
type zipCryptoState struct {
	keys [3]uint32
}

func (z *zipCryptoState) init(password []byte) {
	z.keys[0] = 0x12345678
	z.keys[1] = 0x23456789
	z.keys[2] = 0x34567890
	for _, b := range password {
		z.updateKeys(b)
	}
}

func (z *zipCryptoState) updateKeys(b byte) {
	z.keys[0] = crc32update(z.keys[0], b)
	z.keys[1] = (z.keys[1]+uint32(z.keys[0]&0xff))*134775813 + 1
	z.keys[2] = crc32update(z.keys[2], byte(z.keys[1]>>24))
}

func (z *zipCryptoState) decryptByte(c byte) byte {
	t := z.keys[2] | 2
	p := c ^ byte((t*(t^1))>>8)
	z.updateKeys(p)
	return p
}

func crc32update(p uint32, b byte) uint32 {
	return crc32.IEEETable[(p^uint32(b))&0xff] ^ (p >> 8)
}

// ---------------------------------------------------------------------------
// Worker pool
// ---------------------------------------------------------------------------

func startWorkers(target *crackTarget, passwords <-chan string, stats *Stats, n int) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pw := range passwords {
				if stats.IsFound() {
					// Drain remaining work without further crypto.
					continue
				}
				stats.tried.Add(1)
				if target.tryPassword(pw) {
					stats.SetFound(pw)
				}
			}
		}()
	}
	return &wg
}

// ---------------------------------------------------------------------------
// Progress
// ---------------------------------------------------------------------------

func startProgress(stats *Stats, quiet bool, total uint64) func() {
	if quiet {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(progressInterval)
		defer ticker.Stop()
		start := time.Now()
		for {
			select {
			case <-ticker.C:
				tried := stats.tried.Load()
				elapsed := time.Since(start).Seconds()
				if elapsed <= 0 {
					elapsed = 0.001
				}
				rate := float64(tried) / elapsed
				if total > 0 {
					pct := float64(tried) / float64(total) * 100
					if pct > 100 {
						pct = 100
					}
					var etaStr string
					var remaining float64
					if tried < total {
						remaining = float64(total - tried)
					}
					if rate > 0 && remaining > 0 {
						etaStr = formatDuration(time.Duration(remaining/rate) * time.Second)
					} else {
						etaStr = "—"
					}
					fmt.Fprintf(os.Stderr, "\r[*] %s/%s (%.1f%%) | %.0f/s | elapsed %s | eta %s",
						formatCount(tried), formatCount(total), pct, rate,
						formatDuration(time.Since(start)), etaStr)
				} else {
					fmt.Fprintf(os.Stderr, "\r[*] %s tried | %.0f/s | elapsed %s",
						formatCount(tried), rate, formatDuration(time.Since(start)))
				}
			case <-done:
				fmt.Fprint(os.Stderr, "\r\033[K")
				return
			}
		}
	}()
	return func() { close(done) }
}

func formatCount(n uint64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.2fB", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.2fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.2fK", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// ---------------------------------------------------------------------------
// Attacks
// ---------------------------------------------------------------------------

func attackDictionary(cfg Config, target *crackTarget) {
	var reader io.Reader
	var closer io.Closer

	if cfg.DictFile == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(cfg.DictFile)
		if err != nil {
			fatal("cannot open wordlist: %v", err)
		}
		closer = f
		reader = f
	}
	if closer != nil {
		defer closer.Close()
	}

	stats := &Stats{}
	// Larger buffer keeps workers fed during fast in-memory checks.
	passwords := make(chan string, cfg.Workers*256)
	wg := startWorkers(target, passwords, stats, cfg.Workers)
	stopProgress := startProgress(stats, cfg.Quiet, 0)

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*64), 1024*1024)
	for scanner.Scan() {
		if stats.IsFound() {
			break
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		// Strip a trailing CR for Windows-style wordlists.
		if line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
			if line == "" {
				continue
			}
		}
		passwords <- line
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] wordlist read error: %v\n", err)
	}

	close(passwords)
	wg.Wait()
	stopProgress()
	printResult(stats)
}

func attackBruteforce(cfg Config, target *crackTarget) {
	charset := []byte(cfg.Charset)
	cLen := len(charset)
	if cLen == 0 {
		fatal("empty charset")
	}

	total := bruteforceTotal(cLen, cfg.MinLen, cfg.MaxLen)
	stats := &Stats{}
	passwords := make(chan string, cfg.Workers*256)
	wg := startWorkers(target, passwords, stats, cfg.Workers)
	stopProgress := startProgress(stats, cfg.Quiet, total)

	for length := cfg.MinLen; length <= cfg.MaxLen && !stats.IsFound(); length++ {
		indices := make([]int, length)
		buf := make([]byte, length)
		for !stats.IsFound() {
			for i, idx := range indices {
				buf[i] = charset[idx]
			}
			// string(buf) copies, so reusing buf is safe.
			passwords <- string(buf)

			// Odometer increment.
			pos := length - 1
			for pos >= 0 {
				indices[pos]++
				if indices[pos] < cLen {
					break
				}
				indices[pos] = 0
				pos--
			}
			if pos < 0 {
				break
			}
		}
	}

	close(passwords)
	wg.Wait()
	stopProgress()
	printResult(stats)
}

func bruteforceTotal(charsetLen, minLen, maxLen int) uint64 {
	if charsetLen <= 0 || minLen < 1 || maxLen < minLen {
		return 0
	}
	var total uint64
	pow := uint64(1)
	for l := 1; l <= maxLen; l++ {
		if pow > math.MaxUint64/uint64(charsetLen) {
			return 0 // overflow → unknown total
		}
		pow *= uint64(charsetLen)
		if l >= minLen {
			if total > math.MaxUint64-pow {
				return 0
			}
			total += pow
		}
	}
	return total
}

// ---------------------------------------------------------------------------
// Output / CLI helpers
// ---------------------------------------------------------------------------

func printResult(stats *Stats) {
	tried := stats.tried.Load()
	if stats.IsFound() {
		pw := stats.GetPassword()
		// Metadata on stderr; password alone on stdout (pipe-friendly).
		fmt.Fprintf(os.Stderr, "[+] password found\n")
		fmt.Fprintf(os.Stderr, "[*] candidates tried: %s\n", formatCount(tried))
		_, _ = fmt.Fprintln(os.Stdout, pw)
		os.Exit(exitFound)
	}
	fmt.Fprintf(os.Stderr, "[!] exhausted — password not found (%s candidates tried)\n", formatCount(tried))
	os.Exit(exitNotFound)
}

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", a...)
	os.Exit(exitError)
}

func usage() {
	fmt.Fprintf(os.Stderr, `zipcrack v%s — fast encrypted ZIP password recovery

USAGE
  zipcrack -m <mode> -z <file.zip> [options]

ATTACK MODES
  0  dictionary   try passwords from a wordlist file (or stdin)
  1  brute-force  try all combinations from a character set

OPTIONS
  -m, --attack-mode INT       Attack mode: 0=dictionary, 1=brute-force (required)
  -z, --zip FILE              Target ZIP file (required)
  -w, --wordlist FILE         Wordlist file for mode 0 (use "-" for stdin)
  -1, --custom-charset STR    Custom characters to include (mode 1)
      --increment-min INT     Minimum password length [default: 1]
      --increment-max INT     Maximum password length [default: 6]
  -t, --threads INT           Worker threads [default: %d]
  -q, --quiet                 Suppress progress output
  -v, --version               Print version and exit
  -h, --help                  Show this help

CHARSET SHORTCUTS (mode 1, combinable with --custom-charset)
  -a   lowercase a-z
  -A   uppercase A-Z
  -d   digits 0-9
  -s   special characters  %s

EXAMPLES
  # Dictionary attack
  zipcrack -m 0 -z secret.zip -w rockyou.txt

  # Dictionary from stdin
  cat words.txt | zipcrack -m 0 -z secret.zip -w -

  # Brute-force lowercase + digits, length 4–6
  zipcrack -m 1 -z secret.zip -a -d --increment-min 4 --increment-max 6

  # Custom charset, 16 threads
  zipcrack -m 1 -z secret.zip --custom-charset "abc123!" --increment-max 4 -t 16

EXIT CODES
  0  password found (printed on stdout)
  1  password not found
  2  error (bad args, I/O, invalid zip, ...)
`, version, runtime.NumCPU(), charsetSpecial)
}

// uniqueCharset removes duplicate runes while preserving first-seen order.
func uniqueCharset(s string) string {
	seen := make(map[rune]struct{}, len(s))
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		b.WriteRune(r)
	}
	return b.String()
}

func encName(k encryptionKind) string {
	if k == encAES {
		return "AES"
	}
	return "ZipCrypto"
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	var cfg Config
	var useLower, useUpper, useDigits, useSpecial, showHelp, showVersion bool
	var customCharset string

	fs := flag.NewFlagSet("zipcrack", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage

	fs.IntVar(&cfg.AttackMode, "m", -1, "")
	fs.IntVar(&cfg.AttackMode, "attack-mode", -1, "")
	fs.StringVar(&cfg.ZipFile, "z", "", "")
	fs.StringVar(&cfg.ZipFile, "zip", "", "")
	fs.StringVar(&cfg.DictFile, "w", "", "")
	fs.StringVar(&cfg.DictFile, "wordlist", "", "")
	fs.StringVar(&customCharset, "1", "", "")
	fs.StringVar(&customCharset, "custom-charset", "", "")
	fs.IntVar(&cfg.MinLen, "increment-min", 1, "")
	fs.IntVar(&cfg.MaxLen, "increment-max", 6, "")
	fs.IntVar(&cfg.Workers, "t", runtime.NumCPU(), "")
	fs.IntVar(&cfg.Workers, "threads", runtime.NumCPU(), "")
	fs.BoolVar(&cfg.Quiet, "q", false, "")
	fs.BoolVar(&cfg.Quiet, "quiet", false, "")
	fs.BoolVar(&useLower, "a", false, "")
	fs.BoolVar(&useUpper, "A", false, "")
	fs.BoolVar(&useDigits, "d", false, "")
	fs.BoolVar(&useSpecial, "s", false, "")
	fs.BoolVar(&showHelp, "h", false, "")
	fs.BoolVar(&showHelp, "help", false, "")
	fs.BoolVar(&showVersion, "v", false, "")
	fs.BoolVar(&showVersion, "version", false, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(exitError)
	}

	if showVersion {
		fmt.Printf("zipcrack %s\n", version)
		os.Exit(0)
	}
	if showHelp {
		usage()
		os.Exit(0)
	}

	if cfg.ZipFile == "" || cfg.AttackMode < 0 {
		usage()
		os.Exit(exitError)
	}
	if cfg.MinLen < 1 {
		fatal("--increment-min must be >= 1")
	}
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}

	if st, err := os.Stat(cfg.ZipFile); err != nil {
		fatal("zip file not found: %s", cfg.ZipFile)
	} else if st.IsDir() {
		fatal("zip path is a directory: %s", cfg.ZipFile)
	}

	target, err := loadCrackTarget(cfg.ZipFile)
	if err != nil {
		fatal("%v", err)
	}

	fmt.Fprintf(os.Stderr, "[*] target: %s | entry: %s | encryption: %s | threads: %d\n",
		cfg.ZipFile, target.name, encName(target.kind), cfg.Workers)

	switch cfg.AttackMode {
	case modeDictionary:
		if cfg.DictFile == "" {
			fatal("dictionary mode requires -w/--wordlist (or -w - for stdin)")
		}
		if cfg.DictFile != "-" {
			if st, err := os.Stat(cfg.DictFile); err != nil {
				fatal("wordlist not found: %s", cfg.DictFile)
			} else if st.IsDir() {
				fatal("wordlist path is a directory: %s", cfg.DictFile)
			}
		}
		src := cfg.DictFile
		if src == "-" {
			src = "stdin"
		}
		fmt.Fprintf(os.Stderr, "[*] mode: dictionary | wordlist: %s\n", src)
		attackDictionary(cfg, target)

	case modeBruteforce:
		var cs strings.Builder
		cs.WriteString(customCharset)
		if useLower {
			cs.WriteString(charsetLower)
		}
		if useUpper {
			cs.WriteString(charsetUpper)
		}
		if useDigits {
			cs.WriteString(charsetDigits)
		}
		if useSpecial {
			cs.WriteString(charsetSpecial)
		}
		cfg.Charset = uniqueCharset(cs.String())
		if cfg.Charset == "" {
			fatal("brute-force mode requires a charset (-a, -A, -d, -s, and/or --custom-charset)")
		}
		if cfg.MinLen > cfg.MaxLen {
			fatal("--increment-min (%d) cannot exceed --increment-max (%d)", cfg.MinLen, cfg.MaxLen)
		}
		total := bruteforceTotal(len(cfg.Charset), cfg.MinLen, cfg.MaxLen)
		totalStr := "unknown"
		if total > 0 {
			totalStr = formatCount(total)
		}
		fmt.Fprintf(os.Stderr, "[*] mode: brute-force | charset: %d chars | length: %d-%d | keyspace: %s\n",
			len(cfg.Charset), cfg.MinLen, cfg.MaxLen, totalStr)
		attackBruteforce(cfg, target)

	default:
		fatal("unknown attack mode: %d (use 0=dictionary, 1=brute-force)", cfg.AttackMode)
	}
}
