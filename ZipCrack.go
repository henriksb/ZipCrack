package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/yeka/zip"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

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
		// Once we've reached the desired length, emit the combination.
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

	buffer := new(bytes.Buffer)
	for _, f := range r.File {
		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		defer rc.Close()
		_, err = io.Copy(buffer, rc)
		if err == nil {
			return true
		}
	}
	return false
}

func crack(zipFile string, dictFile string) {
	file, err := os.Open(dictFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	startTime := time.Now()
	count := 0

	var wg sync.WaitGroup
	passwordChan := make(chan string, 1000)
	found := false
	var foundLock sync.Mutex

	// Start worker threads
	numWorkers := 10
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range passwordChan {
				foundLock.Lock()
				if found {
					foundLock.Unlock()
					return
				}
				foundLock.Unlock()

				if unzip(zipFile, password) {
					foundLock.Lock()
					found = true
					foundLock.Unlock()
					fmt.Printf("Password matched: %s\nCombinations tried: %d\nTime taken: %f seconds\n", password, count, time.Since(startTime).Seconds())
					return
				}
			}
		}()
	}

	// Send passwords to workers
	for scanner.Scan() {
		foundLock.Lock()
		if found {
			foundLock.Unlock()
			break
		}
		foundLock.Unlock()

		password := scanner.Text()
		passwordChan <- password
		count++
	}

	close(passwordChan)
	wg.Wait()

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	if !found {
		fmt.Println("Password not found.")
	}
}

func bruteforce(zipFile string, alphabet []string, minLength, maxLength int) {
	startTime := time.Now()
	count := 0
	found := false
	var foundLock sync.Mutex
	var wg sync.WaitGroup

	passwordChan := make(chan string, 1000)
	numWorkers := 10

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range passwordChan {
				foundLock.Lock()
				if found {
					foundLock.Unlock()
					return
				}
				foundLock.Unlock()

				if unzip(zipFile, password) {
					foundLock.Lock()
					found = true
					foundLock.Unlock()
					fmt.Printf("Password matched: %s\nCombinations tried: %d\nTime taken: %f seconds\n", password, count, time.Since(startTime).Seconds())
					return
				}
			}
		}()
	}

	// Iterate over lengths from minLength to maxLength
	for length := minLength; length <= maxLength; length++ {
		combinations := GenerateCombinationsString(alphabet, length)

		for combo := range combinations {
			foundLock.Lock()
			if found {
				foundLock.Unlock()
				break
			}
			foundLock.Unlock()

			password := strings.Join(combo, "")
			passwordChan <- password
			count++
		}

		foundLock.Lock()
		if found {
			foundLock.Unlock()
			break
		}
		foundLock.Unlock()
	}

	// Close the channel and wait for workers to finish
	close(passwordChan)
	wg.Wait()

	elapsed := time.Since(startTime)
	if !found {
		fmt.Println("Password not found! Retry with some different settings.")
	} else {
		fmt.Printf("Total combinations tried: %d in %f seconds\n", count, elapsed.Seconds())
	}
}

func main() {
	zipFile := flag.String("zip", "", "Path to the zip file")
	dictArg := flag.String("dict", "", "Path to dictionary file (if dictionary attack) or characters (if bruteforce)")
	attack := flag.String("attack", "", "Type of attack: 'dictionary' or 'bruteforce'")

	minLength := flag.Int("min-length", 1, "Minimum length for brute force")
	maxLength := flag.Int("max-length", 10, "Maximum length for brute force")

	lower := flag.Bool("lower", false, "Include lowercase letters a-z")
	upper := flag.Bool("upper", false, "Include uppercase letters A-Z")
	numbers := flag.Bool("numbers", false, "Include digits 0-9")
	special := flag.Bool("special", false, "Include special characters")

	flag.Parse()

	if *zipFile == "" || *attack == "" {
		fmt.Printf("\nUsage: %s -zip [zip file] -attack [type]\n\nDictionary example:\n\t%s --zip ExampleFile.zip --dict passwords.txt --attack dictionary\nBrute force example:\n\t%s --zip file.zip --attack bruteforce --min-length 1 --max-length 3 --lower --numbers\n\nBruteforce options (can be combined):\n\t--min-length [int]\n\t--max-length [int]\n\t--lower\n\t--upper\n\t--numbers\n\t--special\n\nThese can be combined for brute force.\n\n", os.Args[0], os.Args[0], os.Args[0])
		os.Exit(1)
	}

	if *attack == "dictionary" {
		if *dictArg == "" {
			log.Fatal("You must specify a dictionary file with -dict when using dictionary attack.")
		}
		fmt.Println("Starting dictionary attack..")
		crack(*zipFile, *dictArg)
	} else if *attack == "bruteforce" {
		// Build the alphabet
		alphabet := ""
		if *dictArg != "" {
			// If dictArg is provided and we are in brute force mode, treat dictArg as characters
			alphabet += *dictArg
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
			fmt.Println("No characters provided for brute force (try --lower, --dict, etc.).")
			os.Exit(1)
		}

		alphabetSlice := strings.Split(alphabet, "")
		fmt.Println("Starting brute force attack..")
		bruteforce(*zipFile, alphabetSlice, *minLength, *maxLength)
	} else {
		os.Exit(1)
	}

	os.Exit(0)
}
