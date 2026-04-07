# ZipCrack

ZipCrack is a command-line tool to crack password protected Zip files without using separate programs like 7zip or Winrar to extract, which makes it a great deal faster.
ZipCracker supports brute force and dictionary attack.

```
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

```
[Download pre-compiled version 2.2 (ELF)](https://github.com/henriksb/ZipCrack/releases/download/2.2/ZipCrack) \
[Download pre-compiled version 2.1 (Windows)](https://github.com/henriksb/ZipCrack/releases/download/2.1/ZipCrack.exe)

Version 2 was tested and estimated to be about 88% faster than version 1.

## Build

```
go mod init ZipCrack
go mod tidy
go build ZipCrack.go
```
