# Warning
Issue with version 2 bruteforce. Use version 1 or create a dictionary until this is fixed.

# ZipCrack

ZipCrack is a command-line tool to crack password protected Zip files without using separate programs like 7zip or Winrar to extract, which makes it a great deal faster.
ZipCracker supports brute force and dictionary attack.

```
Usage: ZipCrack.exe -zip [zip file] -dict [dictionary file/letters] -attack [type of attack]

Example:
        - Dictionary: ZipCrack.exe -zip ExampleFile.zip -dict passwords.txt -attack dictionary
        - Brute force: ZipCrack.exe -zip ExampleFile.zip -dict abcdefghijklmnopqrstuvwxyz -attack bruteforce
```

[Download latest version](https://github.com/henriksb/ZipCrack/releases/download/2/ZipCrack.exe)

Version 2 was tested and estimated to be about 88% faster than version 1.

## Build

```
go mod init ZipCrack
go mod tidy
go build ZipCrack.go
```

## Install -- Linux

```
cp ZipCrack /usr/bin/local
```
