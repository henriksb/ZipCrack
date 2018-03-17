package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Ramshackle-Jamathon/go-kCombinations"
	"github.com/yeka/zip"
)

func unzip(filename string, password string) bool {
	r, err := zip.OpenReader(filename)
	if err != nil {
		return false
	}
	defer r.Close()

	buffer := new(bytes.Buffer)

	for _, f := range r.File {
		f.SetPassword(password)
		r, err := f.Open()
		if err != nil {
			return false
		}
		defer r.Close()
		n, err := io.Copy(buffer, r)
		if n == 0 || err != nil {
			return false
		}
		break
	}
	return true
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

	for scanner.Scan() {
		password := scanner.Text()
		res := unzip(zipFile, password)
		if res == true {
			fmt.Printf("Password matched: %s\nCombinations tried: %d\nTime taken: %f seconds\n", password, count, time.Since(startTime).Seconds())
			return
		}
		count++
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func bruteforce(zipFile string, alphabet []string) {
	startTime := time.Now()
	count := 0

	for i := 1; i <= 10; i++ {
		for combo := range kCombinations.GenerateCombinationsString(alphabet, i) {
			res := unzip(zipFile, strings.Join(combo, ""))
			count++
			if res == true {
				fmt.Printf("Password matched: %s\nCombinations tried: %d\nTime taken: %f seconds\n", strings.Join(combo, ""), count, time.Since(startTime).Seconds())
				return
			}
		}
	}

	fmt.Printf("Password not found! Retry with some different settings.")
	os.Exit(1)

}

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("\nUsage: %s [zip file] [dictionary file/letters] [type of attack]\n\nExample:\n\t- Brute force: %s ExampleFile.zip passwords.txt dictionary\n\t- Dictionary: %s ExampleFile.zip abcdefghijklmnopqrstuvwxyz dictionary\n\n", os.Args[0], os.Args[0], os.Args[0])
		os.Exit(1)
	}

	zipFile := os.Args[1]
	dictFile := os.Args[2]
	attack := os.Args[3]

	if attack == "bruteforce" {
		fmt.Println("Starting brute force attack..")
		alphabet := strings.Split(dictFile, "")
		bruteforce(zipFile, alphabet)
	} else if attack == "dictionary" {
		fmt.Println("Starting dictionary attack..")
		crack(zipFile, dictFile)
	} else {
		os.Exit(1)
	}

	os.Exit(0)
}
