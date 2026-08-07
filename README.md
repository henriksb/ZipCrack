# ZipCrack

ZipCrack is a fast command-line tool for recovering passwords from encrypted ZIP archives. It works entirely in-process (no calls out to 7-Zip/WinRAR), supports **dictionary** and **brute-force** attacks, and understands both traditional **ZipCrypto** and **WinZip AES** encryption.

## Features

- **In-memory verification** — the encrypted entry is loaded once; passwords are tested without reopening the archive
- **Fast ZipCrypto filter** — 12-byte encryption-header check rejects ~255/256 wrong passwords before inflate/CRC
- **Fast AES path** — PBKDF2 password-verification value + HMAC confirmation
- **Dictionary & brute-force** modes (hashcat-style flags)
- **stdin wordlists**, progress with rate/ETA, configurable worker threads
- Pipe-friendly: password on **stdout**, status on **stderr**

## Usage

```
zipcrack -m <mode> -z <file.zip> [options]

Attack modes:
  0  dictionary   try passwords from a wordlist file (or stdin)
  1  brute-force  try all combinations from a character set

Options:
  -m, --attack-mode INT       Attack mode: 0=dictionary, 1=brute-force (required)
  -z, --zip FILE              Target ZIP file (required)
  -w, --wordlist FILE         Wordlist file for mode 0 (use "-" for stdin)
  -1, --custom-charset STR    Custom characters to include (mode 1)
      --increment-min INT     Minimum password length [default: 1]
      --increment-max INT     Maximum password length [default: 6]
  -t, --threads INT           Worker threads [default: NumCPU]
  -q, --quiet                 Suppress progress output
  -v, --version               Print version and exit
  -h, --help                  Show this help

Charset shortcuts (mode 1, combinable with --custom-charset):
  -a   lowercase a-z
  -A   uppercase A-Z
  -d   digits 0-9
  -s   special characters
```

### Examples

```bash
# Dictionary attack
zipcrack -m 0 -z vault.zip -w rockyou.txt

# Dictionary from stdin
cat words.txt | zipcrack -m 0 -z vault.zip -w -

# Brute-force lowercase + digits, length 4–6
zipcrack -m 1 -z vault.zip -a -d --increment-min 4 --increment-max 6

# Custom charset, 16 threads
zipcrack -m 1 -z vault.zip --custom-charset "abc123!" --increment-max 4 -t 16
```

### Exit codes

| Code | Meaning                            |
|------|------------------------------------|
| 0    | Password found (printed on stdout) |
| 1    | Password not found                 |
| 2    | Error (bad args, I/O, invalid zip) |

## Build

```bash
go build -o zipcrack .
```

Requires Go 1.21+.

```bash
go test ./...
```

## Downloads

[Download pre-compiled version 3 Linux](https://github.com/henriksb/ZipCrack/releases/download/3.0/ZipCrack)  

Currently no available binaries for other operating systems, so you'll have to compile it yourself.

Version 2 was tested and estimated to be about 88% faster than version 1.  
Version 3 avoids per-attempt archive I/O and adds early-reject crypto checks for a large additional speedup on ZipCrypto targets.

## License

MIT — see [LICENSE](LICENSE).
