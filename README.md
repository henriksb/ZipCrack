# ZipCrack

ZipCrack is a command-line tool to crack password protected Zip files without using separate programs like 7zip or Winrar to extract, which makes it a great deal faster.
ZipCracker supports brute force and dictionary attack.

```
Dictionary example:
        ZipCrack.exe --zip ExampleFile.zip --dict passwords.txt --attack dictionary
Brute force example:
        ZipCrack.exe --zip ExampleFile.zip --attack bruteforce --min-length 1 --max-length 3 --lower --numbers

Bruteforce options (can be combined):
        --min-length [int]
        --max-length [int]
        --lower
        --upper
        --numbers
        --special

These can be combined for brute force.
```

[Download latest version](https://github.com/henriksb/ZipCrack/releases/download/2.1/ZipCrack.exe)

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

## TODO

- Add --threads parameter to let user allocate as many threads as they want.
- Fix incorrect "Total amount". This is wrong because of threading.
- Add custom bruteforce letters. Currently, you can only choose the inbuilt parameters.
- Save state feature to resume prevoius attempts
