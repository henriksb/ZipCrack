package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yeka/zip"
)

func GenerateCombinationsString(data []string, length int) <-chan []string {
	c := make(chan []string)
	go func(c chan []string) {
		defer close(c)
		combosString(c, []string{}, data, length)
	}(c)
	return c
}

func combosString(c chan []string, combo []string, data []string, length int) {
	if length <= 0 {
		return
	}
	var newCombo []string
	for _, ch := range data {
		newCombo = append(combo, ch)
		if length == 1 {
			output := make([]string, len(newCombo))
			copy(output, newCombo)
			c <- output
		}
		combosString(c, newCombo, data, length-1)
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
				count++
			}
		}()
	}

	// Send passwords to workers
	for scanner.Scan() {
		password := scanner.Text()
		foundLock.Lock()
		if found {
			foundLock.Unlock()
			break
		}
		foundLock.Unlock()
		passwordChan <- password
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

func bruteforce(zipFile string, alphabet []string) {
	startTime := time.Now()
	count := 0
	found := false
	var foundLock sync.Mutex
	var wg sync.WaitGroup
	combinations := GenerateCombinationsString(alphabet, 10)

	passwordChan := make(chan string, 1000)
	numWorkers := 10

	// Start worker threads
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
				count++
			}
		}()
	}

	// Send combinations to password channel
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
	dictFile := flag.String("dict", "", "Path to the dictionary file or characters for brute force")
	attack := flag.String("attack", "", "Type of attack: 'dictionary' or 'bruteforce'")
	flag.Parse()

	if *zipFile == "" || *dictFile == "" || *attack == "" {
		fmt.Printf("\nUsage: %s -zip [zip file] -dict [dictionary file/letters] -attack [type of attack]\n\nExample:\n\t- Dictionary: %s -zip ExampleFile.zip -dict passwords.txt -attack dictionary\n\t- Brute force: %s -zip ExampleFile.zip -dict abcdefghijklmnopqrstuvwxyz -attack bruteforce\n\n", os.Args[0], os.Args[0], os.Args[0])
		os.Exit(1)
	}

	if *attack == "bruteforce" {
		fmt.Println("Starting brute force attack..")
		alphabet := strings.Split(*dictFile, "")
		bruteforce(*zipFile, alphabet)
	} else if *attack == "dictionary" {
		fmt.Println("Starting dictionary attack..")
		crack(*zipFile, *dictFile)
	} else {
		os.Exit(1)
	}

	os.Exit(0)
}
