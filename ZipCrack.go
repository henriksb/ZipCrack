package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/yeka/zip"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type attackState struct {
	Mode             string `json:"mode"`
	DictionaryOffset uint64 `json:"dictionary_offset"`
	BruteforceOffset uint64 `json:"bruteforce_offset"`
	UpdatedAt        string `json:"updated_at"`
}

type stateManager struct {
	path string
	mu   sync.Mutex
}

func (s *stateManager) load() (attackState, error) {
	if s.path == "" {
		return attackState{}, nil
	}
	file, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return attackState{}, nil
		}
		return attackState{}, err
	}

	var state attackState
	if err := json.Unmarshal(file, &state); err != nil {
		return attackState{}, err
	}
	return state, nil
}

func (s *stateManager) save(state attackState) {
	if s.path == "" {
		return
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.WriteFile(s.path, payload, 0o644)
}

func (s *stateManager) clear() {
	if s.path == "" {
		return
	}
	_ = os.Remove(s.path)
}

// GenerateCombinationsString returns a channel of all combinations of `data` of length `length`.
func GenerateCombinationsString(data []string, length int) <-chan []string {
	c := make(chan []string)
	go func() {
		defer close(c)
		combosString(c, []string{}, data, length)
	}()
	return c
}

// combosString is a recursive helper to generate combinations of given length.
func combosString(c chan []string, prefix []string, data []string, length int) {
	if length == 0 {
		combo := make([]string, len(prefix))
		copy(combo, prefix)
		c <- combo
		return
	}

	for _, ch := range data {
		newPrefix := append(prefix, ch)
		combosString(c, newPrefix, data, length-1)
	}
}

func unzip(filename string, password string) bool {
	r, err := zip.OpenReader(filename)
	if err != nil {
		return false
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Flags&0x1 == 0 {
			continue
		}

		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			continue
		}

		_, copyErr := io.Copy(io.Discard, rc)
		closeErr := rc.Close()
		if copyErr == nil && closeErr == nil {
			return true
		}
	}

	return false
}

type passwordJob struct {
	password string
}

func crack(zipFile string, dictFile string, numWorkers int, state *stateManager, resume bool, saveEvery uint64) {
	file, err := os.Open(dictFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	startTime := time.Now()
	var attempted atomic.Uint64
	var found atomic.Bool

	resumeOffset := uint64(0)
	if resume {
		loadedState, err := state.load()
		if err != nil {
			log.Fatalf("failed to load state: %v", err)
		}
		if loadedState.Mode == "dictionary" {
			resumeOffset = loadedState.DictionaryOffset
			fmt.Printf("Resuming dictionary attack from attempt %d\n", resumeOffset)
		}
	}

	var wg sync.WaitGroup
	passwordChan := make(chan passwordJob, numWorkers*100)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range passwordChan {
				if found.Load() {
					return
				}

				currentAttempt := attempted.Add(1)
				if saveEvery > 0 && currentAttempt%saveEvery == 0 {
					state.save(attackState{Mode: "dictionary", DictionaryOffset: currentAttempt})
				}

				if unzip(zipFile, job.password) {
					if !found.Swap(true) {
						fmt.Printf("Password matched: %s\nCombinations tried: %d\nTime taken: %f seconds\n", job.password, currentAttempt, time.Since(startTime).Seconds())
						state.clear()
					}
					return
				}
			}
		}()
	}

	scanner := bufio.NewScanner(file)
	var produced uint64
	for scanner.Scan() {
		if found.Load() {
			break
		}
		if produced < resumeOffset {
			produced++
			continue
		}
		passwordChan <- passwordJob{password: scanner.Text()}
		produced++
	}

	close(passwordChan)
	wg.Wait()

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	if !found.Load() {
		state.save(attackState{Mode: "dictionary", DictionaryOffset: attempted.Load()})
		fmt.Println("Password not found.")
	}
}

func bruteforce(zipFile string, alphabet []string, minLength, maxLength, numWorkers int, state *stateManager, resume bool, saveEvery uint64) {
	startTime := time.Now()
	var attempted atomic.Uint64
	var found atomic.Bool
	var wg sync.WaitGroup

	resumeOffset := uint64(0)
	if resume {
		loadedState, err := state.load()
		if err != nil {
			log.Fatalf("failed to load state: %v", err)
		}
		if loadedState.Mode == "bruteforce" {
			resumeOffset = loadedState.BruteforceOffset
			fmt.Printf("Resuming brute force attack from attempt %d\n", resumeOffset)
		}
	}

	passwordChan := make(chan passwordJob, numWorkers*100)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range passwordChan {
				if found.Load() {
					return
				}

				currentAttempt := attempted.Add(1)
				if saveEvery > 0 && currentAttempt%saveEvery == 0 {
					state.save(attackState{Mode: "bruteforce", BruteforceOffset: currentAttempt})
				}

				if unzip(zipFile, job.password) {
					if !found.Swap(true) {
						fmt.Printf("Password matched: %s\nCombinations tried: %d\nTime taken: %f seconds\n", job.password, currentAttempt, time.Since(startTime).Seconds())
						state.clear()
					}
					return
				}
			}
		}()
	}

	var produced uint64
	for length := minLength; length <= maxLength; length++ {
		if found.Load() {
			break
		}
		combinations := GenerateCombinationsString(alphabet, length)
		for combo := range combinations {
			if found.Load() {
				break
			}
			if produced < resumeOffset {
				produced++
				continue
			}

			password := strings.Join(combo, "")
			passwordChan <- passwordJob{password: password}
			produced++
		}
	}

	close(passwordChan)
	wg.Wait()

	if !found.Load() {
		elapsed := time.Since(startTime)
		state.save(attackState{Mode: "bruteforce", BruteforceOffset: attempted.Load()})
		fmt.Printf("Password not found! Retry with some different settings.\nTotal combinations tried: %d in %f seconds\n", attempted.Load(), elapsed.Seconds())
	}
}

func main() {
	zipFile := flag.String("zip", "", "Path to the zip file")
	dictArg := flag.String("dict", "", "Path to dictionary file (dictionary mode)")
	attack := flag.String("attack", "", "Type of attack: 'dictionary' or 'bruteforce'")

	minLength := flag.Int("min-length", 1, "Minimum length for brute force")
	maxLength := flag.Int("max-length", 10, "Maximum length for brute force")
	threads := flag.Int("threads", runtime.NumCPU(), "Number of worker threads")

	lower := flag.Bool("lower", false, "Include lowercase letters a-z")
	upper := flag.Bool("upper", false, "Include uppercase letters A-Z")
	numbers := flag.Bool("numbers", false, "Include digits 0-9")
	special := flag.Bool("special", false, "Include special characters")
	chars := flag.String("chars", "", "Custom brute force characters to include")

	stateFile := flag.String("state-file", ".zipcrack.state.json", "Path to save resume state")
	resume := flag.Bool("resume", false, "Resume from saved state")
	saveEvery := flag.Uint64("save-every", 1000, "Save progress every N attempts")

	flag.Parse()

	if *zipFile == "" || *attack == "" {
		fmt.Printf("\nUsage: %s -zip [zip file] -attack [type]\n\nDictionary example:\n\t%s --zip ExampleFile.zip --dict passwords.txt --attack dictionary --threads 8\nBrute force example:\n\t%s --zip file.zip --attack bruteforce --min-length 1 --max-length 3 --lower --numbers --chars _$ --threads 16\n\nBruteforce options (can be combined):\n\t--min-length [int]\n\t--max-length [int]\n\t--lower\n\t--upper\n\t--numbers\n\t--special\n\t--chars [string]\n\nGeneral options:\n\t--threads [int]\n\t--resume\n\t--state-file [path]\n\t--save-every [int]\n\n", os.Args[0], os.Args[0], os.Args[0])
		os.Exit(1)
	}

	if *threads < 1 {
		log.Fatal("--threads must be at least 1")
	}

	state := &stateManager{path: *stateFile}

	if *attack == "dictionary" {
		if *dictArg == "" {
			log.Fatal("You must specify a dictionary file with -dict when using dictionary attack.")
		}
		fmt.Println("Starting dictionary attack..")
		crack(*zipFile, *dictArg, *threads, state, *resume, *saveEvery)
	} else if *attack == "bruteforce" {
		alphabet := ""
		if *chars != "" {
			alphabet += *chars
		}
		if *lower {
			alphabet += "abcdefghijklmnopqrstuvwxyz"
		}
		if *upper {
			alphabet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		}
		if *numbers {
			alphabet += "0123456789"
		}
		if *special {
			alphabet += "!@#$%^&*()-_=+[]{}|;:'\",.<>/?\\"
		}

		if alphabet == "" {
			fmt.Println("No characters provided for brute force (try --lower, --chars, etc.).")
			os.Exit(1)
		}

		alphabetSlice := strings.Split(alphabet, "")
		fmt.Println("Starting brute force attack..")
		bruteforce(*zipFile, alphabetSlice, *minLength, *maxLength, *threads, state, *resume, *saveEvery)
	} else {
		log.Fatal("Unknown attack type. Use 'dictionary' or 'bruteforce'.")
	}

	os.Exit(0)
}
