# ZipCrack

ZipCrack is a command-line tool to crack password protected Zip files without using separate programs like 7zip or Winrar to extract, which makes it a great deal faster.
ZipCracker supports brute force and dictionary attack.

```
Usage: ZipCrack.exe <zip file> <dictionary file/letters> <type of attack>

Example:
        - Dictionary: ZipCrack.exe ExampleFile.zip passwords.txt dictionary
        - Brute force: ZipCrack.exe ExampleFile.zip abcdefghijklmnopqrstuvwxyz bruteforce
```

[Download standalone executable](https://github.com/henriksb/ZipCrack/releases/download/1/ZipCrack.exe)

## Build

```
go mod init ZipCrack
go mod tidy
go build ZipCrack.go
```

## Install -- Linux (Thanks [kerszl](https://github.com/kerszl))

```
cp ZipCrack /usr/bin/local
```
