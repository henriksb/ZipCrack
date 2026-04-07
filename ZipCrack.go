package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yeka/zip"
)

const (
	modeDictionary  = 0
	modeBruteforce  = 1
	version         = "2.0.0"
	progressInterval = 3 * time.Second
)

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

// --- Stats (lock-free) ---

type Stats struct {
	tried   atomic.Uint64
	found   atomic.Int32
	password string
	mu       sync.Mutex // only for storing the found password string
}

func (s *Stats) SetFound(pw string) {
	s.mu.Lock()
	s.password = pw
	s.mu.Unlock()
	s.found.Store(1)
}

func (s *Stats) IsFound() bool {
	return s.found.Load() == 1
}

func (s *Stats) GetPassword() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.password
}

// --- Zip verification ---

func tryPassword(zipFile, password string) bool {
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return false
	}
	defer r.Close()

	buf := new(bytes.Buffer)
	for _, f := range r.File {
		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		_, err = io.Copy(buf, rc)
		rc.Close()
		if err == nil {
			return true
		}
		buf.Reset()
	}
	return false
}

// --- Worker pool ---

func startWorkers(zipFile string, passwords <-chan string, stats *Stats, numWorkers int) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pw := range passwords {
				if stats.IsFound() {
					return
				}
				stats.tried.Add(1)
				if tryPassword(zipFile, pw) {
					stats.SetFound(pw)
					return
				}
			}
		}()
	}
	return &wg
}

// --- Progress reporter ---

func startProgress(stats *Stats, quiet bool) func() {
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
					rate := float64(tried) / elapsed
					fmt.Fprintf(os.Stderr, "\r[*] %d tried | %.0f/s | %.1fs elapsed", tried, rate, elapsed)
				case <-done:
					fmt.Fprint(os.Stderr, "\r\033[K") // clear line
					return
			}
		}
	}()
	return func() { close(done) }
}

// --- Dictionary attack ---

func attackDictionary(cfg Config) {
	file, err := os.Open(cfg.DictFile)
	if err != nil {
		fatal("Cannot open dictionary: %v", err)
	}
	defer file.Close()

	stats := &Stats{}
	passwords := make(chan string, cfg.Workers*64)
	wg := startWorkers(cfg.ZipFile, passwords, stats, cfg.Workers)
	stopProgress := startProgress(stats, cfg.Quiet)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		if stats.IsFound() {
			break
		}
		passwords <- scanner.Text()
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] Scanner error: %v\n", err)
	}

	close(passwords)
	wg.Wait()
	stopProgress()
	printResult(stats)
}

// --- Brute-force attack ---

func attackBruteforce(cfg Config) {
	charset := []byte(cfg.Charset)
	cLen := len(charset)

	stats := &Stats{}
	passwords := make(chan string, cfg.Workers*64)
	wg := startWorkers(cfg.ZipFile, passwords, stats, cfg.Workers)
	stopProgress := startProgress(stats, cfg.Quiet)

	// Iterative generation — no recursion, no goroutine overhead
	for length := cfg.MinLen; length <= cfg.MaxLen && !stats.IsFound(); length++ {
		indices := make([]int, length)
		buf := make([]byte, length)
		for {
			if stats.IsFound() {
				break
			}
			// Build password from current indices
			for i, idx := range indices {
				buf[i] = charset[idx]
			}
			passwords <- string(buf)

			// Increment indices (odometer-style)
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
				break // All combinations for this length exhausted
			}
		}
	}

	close(passwords)
	wg.Wait()
	stopProgress()
	printResult(stats)
}

// --- Output ---

func printResult(stats *Stats) {
	tried := stats.tried.Load()
	if stats.IsFound() {
		fmt.Printf("\n%s\n\n", stats.GetPassword())
		fmt.Fprintf(os.Stderr, "[+] Password found\n")
		fmt.Fprintf(os.Stderr, "[*] Candidates tried: %d\n", tried)
	} else {
		fmt.Fprintf(os.Stderr, "[!] Exhausted — password not found (%d candidates tried)\n", tried)
	}
}

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", a...)
	os.Exit(1)
}

// --- CLI ---

func usage() {
	fmt.Fprintf(os.Stderr, `zipcrack v%s — encrypted zip password recovery

	Usage:
	zipcrack [options]

	Options:
	-m, --attack-mode  INT   Attack mode: 0 = dictionary, 1 = brute-force (required)
	-z, --zip          FILE  Target zip file (required)
	-w, --wordlist     FILE  Wordlist / dictionary file (mode 0)
	-1, --custom-charset STR Custom character set (mode 1)
	--increment-min INT  Minimum password length [default: 1]
	--increment-max INT  Maximum password length [default: 6]
	-t, --threads      INT   Worker threads [default: NumCPU]
	-q, --quiet              Suppress progress output

	Built-in charsets for mode 1 (combine with --custom-charset):
	-a  lowercase (a-z)
	-A  uppercase (A-Z)
	-d  digits (0-9)
	-s  special characters

	Examples:
	zipcrack -m 0 -z vault.zip -w rockyou.txt
	zipcrack -m 1 -z vault.zip -a -d --increment-min 4 --increment-max 6
	zipcrack -m 1 -z vault.zip --custom-charset "abc123!" --increment-max 4 -t 16
	`, version)
}

func main() {
	var cfg Config
	var useLower, useUpper, useDigits, useSpecial, showHelp bool
	var customCharset string

	flag.IntVar(&cfg.AttackMode, "m", -1, "")
	flag.IntVar(&cfg.AttackMode, "attack-mode", -1, "")
	flag.StringVar(&cfg.ZipFile, "z", "", "")
	flag.StringVar(&cfg.ZipFile, "zip", "", "")
	flag.StringVar(&cfg.DictFile, "w", "", "")
	flag.StringVar(&cfg.DictFile, "wordlist", "", "")
	flag.StringVar(&customCharset, "1", "", "")
	flag.StringVar(&customCharset, "custom-charset", "", "")
	flag.IntVar(&cfg.MinLen, "increment-min", 1, "")
	flag.IntVar(&cfg.MaxLen, "increment-max", 6, "")
	flag.IntVar(&cfg.Workers, "t", runtime.NumCPU(), "")
	flag.IntVar(&cfg.Workers, "threads", runtime.NumCPU(), "")
	flag.BoolVar(&cfg.Quiet, "q", false, "")
	flag.BoolVar(&cfg.Quiet, "quiet", false, "")
	flag.BoolVar(&useLower, "a", false, "")
	flag.BoolVar(&useUpper, "A", false, "")
	flag.BoolVar(&useDigits, "d", false, "")
	flag.BoolVar(&useSpecial, "s", false, "")
	flag.BoolVar(&showHelp, "h", false, "")
	flag.BoolVar(&showHelp, "help", false, "")

	flag.Usage = usage
	flag.Parse()

	if showHelp {
		usage()
		os.Exit(0)
	}

	// Validate required args
	if cfg.ZipFile == "" || cfg.AttackMode < 0 {
		usage()
		os.Exit(1)
	}

	if _, err := os.Stat(cfg.ZipFile); os.IsNotExist(err) {
		fatal("Zip file not found: %s", cfg.ZipFile)
	}

	if cfg.Workers < 1 {
		cfg.Workers = 1
	}

	switch cfg.AttackMode {
		case modeDictionary:
			if cfg.DictFile == "" {
				fatal("Dictionary mode requires -w/--wordlist")
			}
			if _, err := os.Stat(cfg.DictFile); os.IsNotExist(err) {
				fatal("Wordlist not found: %s", cfg.DictFile)
			}
			fmt.Fprintf(os.Stderr, "[*] Mode: dictionary | Wordlist: %s | Threads: %d\n", cfg.DictFile, cfg.Workers)
			attackDictionary(cfg)

		case modeBruteforce:
			var charset strings.Builder
			charset.WriteString(customCharset)
			if useLower {
				charset.WriteString("abcdefghijklmnopqrstuvwxyz")
			}
			if useUpper {
				charset.WriteString("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
			}
			if useDigits {
				charset.WriteString("0123456789")
			}
			if useSpecial {
				charset.WriteString("!@#$%^&*()-_=+[]{}|;:'\",.<>/?\\")
			}
			cfg.Charset = charset.String()

			if cfg.Charset == "" {
				fatal("Brute-force mode requires a charset (-a, -d, -s, -A, or --custom-charset)")
			}
			if cfg.MinLen > cfg.MaxLen {
				fatal("--increment-min (%d) cannot exceed --increment-max (%d)", cfg.MinLen, cfg.MaxLen)
			}

			fmt.Fprintf(os.Stderr, "[*] Mode: brute-force | Charset len: %d | Length: %d-%d | Threads: %d\n",
				    len(cfg.Charset), cfg.MinLen, cfg.MaxLen, cfg.Workers)
			attackBruteforce(cfg)

		default:
			fatal("Unknown attack mode: %d (use 0=dictionary, 1=bruteforce)", cfg.AttackMode)
	}
}
