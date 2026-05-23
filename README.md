# Go RCE Detector

A lightweight static analysis tool written in Go that detects potential **Remote Code Execution (RCE)** vulnerabilities in Go applications.

---

## What it detects

- exec.Command usage
- Shell execution patterns (`sh -c`, `bash -c`, `cmd.exe /C`)
- Dynamic input passed into command execution
- Potential command injection risks

---

## Why this matters

RCE vulnerabilities allow attackers to execute system commands on the server.

This tool helps developers identify risky code patterns before deployment.

---

## How it works

- Parses Go source code using AST (Abstract Syntax Tree)
- Scans function calls to `exec.Command`
- Analyzes arguments for unsafe patterns
- Flags severity levels:
  - LOW
  - HIGH
  - CRITICAL

---

## Usage

```bash
go run main.go ./testdata

[CRITICAL]
File: testdata/test.go:12
Issue: RCE: shell execution via -c


[HIGH]
File: testdata/test.go:18
Issue: RCE risk: dynamic input in exec.Command