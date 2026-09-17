# CyberGuard 8086

**An educational cybersecurity utility suite built in 8086 Assembly for Emu8086.**

Independently implemented by **MD TASHDID NAYEEM** for the **Microprocessors** course at **BRAC University**, CyberGuard 8086 connects low-level programming with simplified security concepts through a menu-driven DOS application.

## Why I built it

My background in cybersecurity includes vulnerability assessment and penetration testing, bug bounty research, and security automation. I built CyberGuard 8086 to connect that experience with 8086 Assembly programming and showcase the implementation of security-themed logic using registers, arrays, procedures, and byte-level operations.

## Features

| Module | Implementation |
| --- | --- |
| Password Strength Analyzer | Scores five checks: length of at least eight characters, uppercase, lowercase, digits, and printable non-alphanumeric characters. Reports Weak, Medium, or Strong. |
| Firewall Rule & Port Access Simulator | Looks up TCP/UDP and port combinations in a 12-entry rule table; displays a service, ALLOW/BLOCK decision, and configured risk level. Unmatched combinations default to BLOCK. |
| XOR Text Encryption & Decryption | Applies a numeric key from 1–9 to each message byte, displays hexadecimal ciphertext, and recovers the stored message after a matching-key check. |
| Signature-Based Threat Scanner | Performs case-insensitive substring searches for six keywords: virus, trojan, malware, keylogger, ransomware, and exploit. Counts distinct matched keywords. |

## Technical concepts

- Arrays and indexed addressing for input buffers, ciphertext, and rule tables.
- Procedures with `CALL` / `RET` and stack operations with `PUSH` / `POP`.
- ASCII character classification and case conversion.
- Loops, conditional jumps, counters, and table lookup.
- Unsigned 16-bit decimal parsing with overflow detection.
- Bitwise XOR, hexadecimal output, and DOS `INT 21h` input/output.

## Run locally

1. Open **Emu8086** on a compatible system.
2. Open `CyberGuard8086.asm`.
3. Compile the program using its `#make_COM#` directive and `org 100h` entry layout.
4. Start the emulator and run the program.
5. Enter a menu option from 1–4, followed by Enter. Choose 5 to exit.

The source targets Emu8086 and a DOS `.COM` execution environment. It is not a native modern Windows/Linux executable.

## Example walkthrough

- Analyze `Cyber@123`: expected score **5/5**, **STRONG**.
- Simulate **TCP port 443**: expected **HTTPS / ALLOW / LOW**.
- Encrypt `HELLO` with key `5`: expected bytes **4D 40 49 49 4A**; decrypt with key `5` to recover `HELLO`.
- Scan `malware exploit found in sample`: expected **2** distinct matches and **HIGH**.

See [manual test cases](docs/DEMO_TEST_CASES.md) and [demo recording guide](docs/DEMO_GUIDE.md).

## Educational limitations

- The firewall is a rule-lookup simulation; it does not inspect or block network traffic. Risk labels are fixed demo values, not real-world security assessments.
- The scanner searches typed text for keywords. It does not inspect files or detect actual malware. Its `SAFE` label means only that no configured keyword matched; even `antivirus` matches `virus`.
- Repeated single-byte XOR with nine possible keys is not secure encryption. The key remains in memory, and the matching-key check is application logic.
- Password scoring is a simple checklist, not an entropy estimate or breach check. Spaces count as special characters. Input is visible on screen; use example passwords only.
- Input limits are 40 characters for passwords, 80 for messages, and 100 for scanned text. Extra characters are ignored once the input limit is reached, so overlong numeric input can be interpreted as its accepted prefix.
- Data is kept in memory for the current session only.

## Validation status

The portfolio documentation was checked against the supplied Assembly source. Emu8086 compilation and execution have not been independently verified during this packaging review. Demo outputs are expected results, not an execution log.

## Academic context

Developed for the Microprocessors course and published as a portfolio project. Although the course assignment was organized for a two-person group, the complete software implementation was carried out independently by MD TASHDID NAYEEM.

Readers should use the project to understand the implementation and follow their own institution’s academic-integrity requirements.


## Demo Screenshots

[View screenshots of all four features (PDF)](screenshots/CyberGuard8086.pdf)


## Author

**MD TASHDID NAYEEM** — Cybersecurity professional and Computer Science & Engineering student at BRAC University.

- [LinkedIn](https://www.linkedin.com/in/muhammad-tashdid-nayeem/)
- [Portfolio](https://tashdidnayeem.carrd.co/)

