# Manual demo test cases

These are expected results; record actual results after running in Emu8086.

```text
CYBERGUARD 8086 - DEMO TEST CASES
=================================

FEATURE 1 - PASSWORD STRENGTH ANALYZER
--------------------------------------
Test 1:
Input: abc
Expected: score 1/5 (lowercase only), WEAK.

Test 2:
Input: Hello123
Expected: length YES, uppercase YES, lowercase YES, number YES,
special NO -> score 4/5, MEDIUM.

Test 3:
Input: Cyber@123
Expected: all five checks YES -> score 5/5, STRONG.

FEATURE 2 - FIREWALL RULE & PORT ACCESS SIMULATOR
-------------------------------------------------
Test 1:
Protocol: TCP (1)
Port: 443
Expected: Service HTTPS, Rule ALLOW, Risk LOW, permitted.

Test 2:
Protocol: TCP (1)
Port: 23
Expected: Service TELNET, Rule BLOCK, Risk HIGH, blocked.

Test 3:
Protocol: UDP (2)
Port: 53
Expected: Service DNS, Rule ALLOW, Risk LOW, permitted.

Test 4:
Protocol: TCP (1)
Port: 9999
Expected: Unknown service, default BLOCK, HIGH risk.

FEATURE 3 - XOR TEXT ENCRYPTION & DECRYPTION
--------------------------------------------
Test 1:
Plaintext: HELLO
Key: 5
Expected ciphertext hex:
4D 40 49 49 4A
Then choose decrypt and enter key 5.
Expected recovered plaintext: HELLO

Test 2:
After encryption, enter a different key during decryption.
Expected: Wrong key / decryption rejected.

FEATURE 4 - SIGNATURE-BASED THREAT SCANNER
------------------------------------------
Test 1:
Input: student project document
Expected: no signatures, count 0, SAFE.

Test 2:
Input: possible Trojan sample
Expected: TROJAN detected, count 1, MEDIUM.

Test 3:
Input: malware exploit found in sample
Expected: MALWARE and EXPLOIT detected, count 2, HIGH.

Test 4 (case-insensitive test):
Input: RANSOMWARE and KeyLogger indicators
Expected: RANSOMWARE + KEYLOGGER detected, count 2, HIGH.

```

Additional checks: reject port 65536; reject an empty port; attempt decryption before encryption; scan repeated `virus virus` (one distinct match); test input limits and backspace. Overlong input is truncated by the input reader rather than rejected as a whole.
