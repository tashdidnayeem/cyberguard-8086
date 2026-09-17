; ============================================================================
; CyberGuard 8086 - Cybersecurity Utility Suite
; Microprocessors Course Project
; Implementation: MD TASHDID NAYEEM
; Platform: Emu8086 / 8086 Assembly Language (DOS .COM program)
;
; FEATURE SET (4 major features)
;   1. Password Strength Analyzer
;   2. Firewall Rule & Port Access Simulator
;   3. XOR Text Encryption & Decryption System
;   4. Signature-Based Threat Scanner
;
; Course requirements covered:
;   - Arrays: password/message/firewall-rule/signature/input buffers
;   - Procedures: each feature and utility is implemented as procedures
;   - Stack: used by CALL/RET and PUSH/POP inside procedures
;   - Logic: loops, comparisons, ASCII processing, XOR, table lookup,
;            substring search, counters and conditional jumps
; ============================================================================

#make_COM#
org 100h
jmp start

; ---------------------------------------------------------------------------
; GLOBAL BUFFERS / ARRAYS
; ---------------------------------------------------------------------------
menuBuf       db 3 dup(0)
passwordBuf   db 41 dup(0)
portBuf       db 7 dup(0)
messageBuf    db 81 dup(0)
encryptedBuf  db 81 dup(0)
decryptedBuf  db 81 dup(0)
keyBuf        db 3 dup(0)
scanBuf       db 101 dup(0)

; ---------------------------------------------------------------------------
; PASSWORD ANALYZER STATE
; ---------------------------------------------------------------------------
flagLength    db 0
flagUpper     db 0
flagLower     db 0
flagDigit     db 0
flagSpecial   db 0
strengthScore db 0

; ---------------------------------------------------------------------------
; FIREWALL SIMULATOR DATA
; Protocol codes: 1 = TCP, 2 = UDP
; Action codes  : 0 = BLOCK, 1 = ALLOW
; Risk codes    : 1 = LOW, 2 = MEDIUM, 3 = HIGH
; ---------------------------------------------------------------------------
rulePorts   dw 21, 22, 23, 25, 53, 80, 123, 161, 443, 445, 3389, 8080
ruleProto   db 1,  1,  1,  1,  2,  1,  2,   2,   1,   1,    1,    1
ruleAction  db 0,  0,  0,  1,  1,  1,  1,   0,   1,   0,    0,    0
ruleRisk    db 3,  2,  3,  2,  1,  1,  1,   3,   1,   3,    3,    2

protocolValue db 0
portValue     dw 0
fwAction      db 0
fwRisk        db 0
fwFound       db 0

; ---------------------------------------------------------------------------
; ENCRYPTION STATE
; ---------------------------------------------------------------------------
messageLen     db 0
storedKey      db 0
hasEncrypted   db 0

; ---------------------------------------------------------------------------
; THREAT SCANNER DATA
; Signatures are intentionally simple educational signatures.
; ---------------------------------------------------------------------------
sigVirus       db 'virus'
sigTrojan      db 'trojan'
sigMalware     db 'malware'
sigKeylogger   db 'keylogger'
sigRansomware  db 'ransomware'
sigExploit     db 'exploit'

foundCount     db 0

; ---------------------------------------------------------------------------
; COMMON STRINGS
; ---------------------------------------------------------------------------
crlf db 13,10,'$'
line db '============================================================',13,10,'$'
smallLine db '------------------------------------------------------------',13,10,'$'
pressEnter db 13,10,'Press ENTER to return to the main menu...$'
invalidChoice db 13,10,'[-] Invalid option. Please try again.',13,10,'$'

welcome1 db 13,10,'============================================================',13,10,'$'
welcome2 db '                    CYBERGUARD 8086',13,10,'$'
welcome3 db '                 CYBERSECURITY UTILITY SUITE',13,10,'$'
welcome4 db '============================================================',13,10,'$'
welcome5 db 'Educational security tools implemented in 8086 Assembly.',13,10,'$'

menuTitle db 13,10,'============================================================',13,10,'$'
menuHead  db '                         MAIN MENU',13,10,'$'
menuLine  db '============================================================',13,10,'$'
menu1 db '1. Password Strength Analyzer',13,10,'$'
menu2 db '2. Firewall Rule & Port Access Simulator',13,10,'$'
menu3 db '3. XOR Text Encryption & Decryption System',13,10,'$'
menu4 db '4. Signature-Based Threat Scanner',13,10,'$'
menu5 db '5. Exit',13,10,'$'
menuPrompt db 13,10,'Select option (1-5): $'
exitMsg db 13,10,'[+] CyberGuard session ended. Goodbye.',13,10,'$'

; ---------------------------------------------------------------------------
; FEATURE 1 STRINGS - PASSWORD STRENGTH ANALYZER
; ---------------------------------------------------------------------------
passTitle db 13,10,'============================================================',13,10,'$'
passHead db '                 PASSWORD STRENGTH ANALYZER',13,10,'$'
passPrompt db 'Enter a password (max 40 characters): $'
labelLength db 13,10,'Length >= 8        : $'
labelUpper db 13,10,'Uppercase A-Z      : $'
labelLower db 13,10,'Lowercase a-z      : $'
labelDigit db 13,10,'Number 0-9         : $'
labelSpecial db 13,10,'Special character  : $'
yesMsg db 'YES$'
noMsg db 'NO$'
scoreMsg db 13,10,'Security Score     : $'
outOfFive db '/5',13,10,'$'
strengthMsg db 'Password Strength  : $'
weakMsg db 'WEAK',13,10,'$'
mediumMsg db 'MEDIUM',13,10,'$'
strongMsg db 'STRONG',13,10,'$'
passAdviceWeak db 'Advice: Add more character types and increase the length.',13,10,'$'
passAdviceMedium db 'Advice: Good start, but satisfy all five security checks.',13,10,'$'
passAdviceStrong db 'Advice: This password satisfies all configured checks.',13,10,'$'

; ---------------------------------------------------------------------------
; FEATURE 2 STRINGS - FIREWALL SIMULATOR
; ---------------------------------------------------------------------------
fwTitle db 13,10,'============================================================',13,10,'$'
fwHead db '              FIREWALL RULE & PORT ACCESS SIMULATOR',13,10,'$'
fwProtocolPrompt db 'Select protocol: 1 = TCP, 2 = UDP : $'
fwPortPrompt db 'Enter destination port (0-65535): $'
fwInvalidProtocol db '[-] Invalid protocol. Enter 1 or 2.',13,10,'$'
fwInvalidPort db '[-] Invalid port. Enter a number from 0 to 65535.',13,10,'$'
fwResult db 13,10,'Firewall Analysis',13,10,'$'
fwProtocolLabel db 'Protocol : $'
fwPortLabel db 'Port     : $'
fwServiceLabel db 'Service  : $'
fwRuleLabel db 'Rule     : $'
fwRiskLabel db 'Risk     : $'
fwDecisionLabel db 'Decision : $'
tcpMsg db 'TCP',13,10,'$'
udpMsg db 'UDP',13,10,'$'
allowMsg db 'ALLOW',13,10,'$'
blockMsg db 'BLOCK',13,10,'$'
lowMsg db 'LOW',13,10,'$'
medMsg db 'MEDIUM',13,10,'$'
highMsg db 'HIGH',13,10,'$'
unknownService db 'Unknown / Unlisted Service',13,10,'$'
unknownRuleMsg db 'No exact rule found. Default policy = BLOCK.',13,10,'$'
allowedDecision db '[+] Connection would be permitted by the simulated firewall.',13,10,'$'
blockedDecision db '[!] Connection would be blocked by the simulated firewall.',13,10,'$'

svcFTP db 'FTP',13,10,'$'
svcSSH db 'SSH',13,10,'$'
svcTELNET db 'TELNET',13,10,'$'
svcSMTP db 'SMTP',13,10,'$'
svcDNS db 'DNS',13,10,'$'
svcHTTP db 'HTTP',13,10,'$'
svcNTP db 'NTP',13,10,'$'
svcSNMP db 'SNMP',13,10,'$'
svcHTTPS db 'HTTPS',13,10,'$'
svcSMB db 'SMB',13,10,'$'
svcRDP db 'RDP',13,10,'$'
svcHTTPALT db 'HTTP-ALT',13,10,'$'

; ---------------------------------------------------------------------------
; FEATURE 3 STRINGS - XOR ENCRYPTION / DECRYPTION
; ---------------------------------------------------------------------------
cryptoTitle db 13,10,'============================================================',13,10,'$'
cryptoHead db '              XOR TEXT ENCRYPTION / DECRYPTION',13,10,'$'
cryptoMenu1 db '1. Encrypt a new message',13,10,'$'
cryptoMenu2 db '2. Decrypt the stored message',13,10,'$'
cryptoMenu3 db '3. Return to main menu',13,10,'$'
cryptoPrompt db 'Select option (1-3): $'
msgPrompt db 'Enter plaintext (max 80 characters): $'
keyPrompt db 'Enter one-digit XOR key (1-9): $'
invalidKey db '[-] Invalid key. Enter one digit from 1 to 9.',13,10,'$'
encryptSuccess db 13,10,'[+] Encryption completed.',13,10,'$'
cipherLabel db 'Ciphertext (HEX): $'
noEncrypted db 13,10,'[-] No encrypted message is stored. Encrypt first.',13,10,'$'
decKeyPrompt db 'Enter decryption key (1-9): $'
wrongKey db '[-] Wrong key. Decryption rejected.',13,10,'$'
decryptSuccess db 13,10,'[+] Decryption completed.',13,10,'$'
plainLabel db 'Recovered plaintext: $'

; ---------------------------------------------------------------------------
; FEATURE 4 STRINGS - SIGNATURE THREAT SCANNER
; ---------------------------------------------------------------------------
scanTitle db 13,10,'============================================================',13,10,'$'
scanHead db '                 SIGNATURE-BASED THREAT SCANNER',13,10,'$'
scanPrompt db 'Enter text/data to scan (max 100 characters): $'
scanWorking db 13,10,'Scanning for known suspicious signatures...',13,10,'$'
scanFoundHeader db 13,10,'Detected signatures:',13,10,'$'
scanNone db '  None',13,10,'$'
scanPrefix db '  [!] $'
scanVirusMsg db 'VIRUS',13,10,'$'
scanTrojanMsg db 'TROJAN',13,10,'$'
scanMalwareMsg db 'MALWARE',13,10,'$'
scanKeyloggerMsg db 'KEYLOGGER',13,10,'$'
scanRansomwareMsg db 'RANSOMWARE',13,10,'$'
scanExploitMsg db 'EXPLOIT',13,10,'$'
matchCountLabel db 13,10,'Signature matches : $'
threatLevelLabel db 'Threat level      : $'
threatSafe db 'SAFE',13,10,'$'
threatMedium db 'MEDIUM',13,10,'$'
threatHigh db 'HIGH',13,10,'$'
threatSafeInfo db '[+] No configured malicious signature was detected.',13,10,'$'
threatMediumInfo db '[!] One suspicious signature was detected. Review the data.',13,10,'$'
threatHighInfo db '[!] Multiple suspicious signatures detected. High-risk input.',13,10,'$'

; ===========================================================================
; PROGRAM ENTRY
; ===========================================================================
start:
    ; In a .COM program code and data share the same segment.
    push cs
    pop ds
    push cs
    pop es

    lea dx, welcome1
    call PrintString
    lea dx, welcome2
    call PrintString
    lea dx, welcome3
    call PrintString
    lea dx, welcome4
    call PrintString
    lea dx, welcome5
    call PrintString

main_menu:
    call ShowMainMenu
    call ReadSingleKey

    cmp al, '1'
    je do_password
    cmp al, '2'
    je do_firewall
    cmp al, '3'
    je do_crypto
    cmp al, '4'
    je do_scanner
    cmp al, '5'
    je program_exit

    lea dx, invalidChoice
    call PrintString
    call PauseForEnter
    jmp main_menu

do_password:
    call PasswordAnalyzer
    call PauseForEnter
    jmp main_menu

do_firewall:
    call FirewallSimulator
    call PauseForEnter
    jmp main_menu

do_crypto:
    call CryptoSystem
    jmp main_menu

do_scanner:
    call ThreatScanner
    call PauseForEnter
    jmp main_menu

program_exit:
    lea dx, exitMsg
    call PrintString
    mov ax, 4C00h
    int 21h

; ===========================================================================
; FEATURE 1: PASSWORD STRENGTH ANALYZER
; Checks 5 independent rules and produces Weak / Medium / Strong classification.
; ===========================================================================
PasswordAnalyzer proc near
    lea dx, passTitle
    call PrintString
    lea dx, passHead
    call PrintString
    lea dx, menuLine
    call PrintString
    lea dx, passPrompt
    call PrintString

    lea di, passwordBuf
    mov cx, 40
    call ReadLineEcho              ; BX = entered length

    mov byte ptr [flagLength], 0
    mov byte ptr [flagUpper], 0
    mov byte ptr [flagLower], 0
    mov byte ptr [flagDigit], 0
    mov byte ptr [flagSpecial], 0
    mov byte ptr [strengthScore], 0

    cmp bx, 8
    jb pa_scan
    mov byte ptr [flagLength], 1

pa_scan:
    lea si, passwordBuf
    mov cx, bx
    jcxz pa_score

pa_loop:
    mov al, [si]

    cmp al, 'A'
    jb pa_lower
    cmp al, 'Z'
    ja pa_lower
    mov byte ptr [flagUpper], 1
    jmp pa_next

pa_lower:
    cmp al, 'a'
    jb pa_digit
    cmp al, 'z'
    ja pa_digit
    mov byte ptr [flagLower], 1
    jmp pa_next

pa_digit:
    cmp al, '0'
    jb pa_special
    cmp al, '9'
    ja pa_special
    mov byte ptr [flagDigit], 1
    jmp pa_next

pa_special:
    ; Any printable non-alphanumeric character counts as a special character.
    cmp al, 32
    jb pa_next
    cmp al, 126
    ja pa_next
    mov byte ptr [flagSpecial], 1

pa_next:
    inc si
    loop pa_loop

pa_score:
    xor ax, ax
    mov al, [flagLength]
    add al, [flagUpper]
    add al, [flagLower]
    add al, [flagDigit]
    add al, [flagSpecial]
    mov [strengthScore], al

    lea dx, labelLength
    call PrintString
    mov al, [flagLength]
    call PrintYesNo

    lea dx, labelUpper
    call PrintString
    mov al, [flagUpper]
    call PrintYesNo

    lea dx, labelLower
    call PrintString
    mov al, [flagLower]
    call PrintYesNo

    lea dx, labelDigit
    call PrintString
    mov al, [flagDigit]
    call PrintYesNo

    lea dx, labelSpecial
    call PrintString
    mov al, [flagSpecial]
    call PrintYesNo

    lea dx, scoreMsg
    call PrintString
    mov al, [strengthScore]
    xor ah, ah
    call PrintNumber
    lea dx, outOfFive
    call PrintString

    lea dx, strengthMsg
    call PrintString
    mov al, [strengthScore]
    cmp al, 2
    jbe pa_weak
    cmp al, 4
    jbe pa_medium

    lea dx, strongMsg
    call PrintString
    lea dx, passAdviceStrong
    call PrintString
    ret

pa_weak:
    lea dx, weakMsg
    call PrintString
    lea dx, passAdviceWeak
    call PrintString
    ret

pa_medium:
    lea dx, mediumMsg
    call PrintString
    lea dx, passAdviceMedium
    call PrintString
    ret
PasswordAnalyzer endp

; ===========================================================================
; FEATURE 2: FIREWALL RULE & PORT ACCESS SIMULATOR
; Uses arrays as a rule table. Unknown traffic follows default-deny policy.
; ===========================================================================
FirewallSimulator proc near
    lea dx, fwTitle
    call PrintString
    lea dx, fwHead
    call PrintString
    lea dx, menuLine
    call PrintString

fw_read_protocol:
    lea dx, fwProtocolPrompt
    call PrintString
    call ReadSingleKey
    cmp al, '1'
    je fw_tcp
    cmp al, '2'
    je fw_udp
    lea dx, fwInvalidProtocol
    call PrintString
    jmp fw_read_protocol

fw_tcp:
    mov byte ptr [protocolValue], 1
    jmp fw_read_port

fw_udp:
    mov byte ptr [protocolValue], 2

fw_read_port:
    lea dx, fwPortPrompt
    call PrintString
    lea di, portBuf
    mov cx, 5
    call ReadLineEcho              ; BX = string length
    lea si, portBuf
    call ParseUnsigned16           ; AX = value, CF=1 if invalid
    jc fw_bad_port
    mov [portValue], ax
    jmp fw_find_rule

fw_bad_port:
    lea dx, fwInvalidPort
    call PrintString
    jmp fw_read_port

fw_find_rule:
    mov byte ptr [fwFound], 0
    mov byte ptr [fwAction], 0     ; default deny
    mov byte ptr [fwRisk], 3       ; unknown/unlisted treated as high risk

    lea si, rulePorts
    xor bx, bx                     ; BX = rule index
    mov cx, 12

fw_rule_loop:
    mov ax, [si]
    cmp ax, [portValue]
    jne fw_next_rule

    lea di, ruleProto
    add di, bx
    mov al, [di]
    cmp al, [protocolValue]
    jne fw_next_rule

    mov byte ptr [fwFound], 1

    lea di, ruleAction
    add di, bx
    mov al, [di]
    mov [fwAction], al

    lea di, ruleRisk
    add di, bx
    mov al, [di]
    mov [fwRisk], al
    jmp fw_show_result

fw_next_rule:
    add si, 2
    inc bx
    loop fw_rule_loop

fw_show_result:
    lea dx, fwResult
    call PrintString
    lea dx, smallLine
    call PrintString

    lea dx, fwProtocolLabel
    call PrintString
    cmp byte ptr [protocolValue], 1
    jne fw_show_udp
    lea dx, tcpMsg
    call PrintString
    jmp fw_show_port
fw_show_udp:
    lea dx, udpMsg
    call PrintString

fw_show_port:
    lea dx, fwPortLabel
    call PrintString
    mov ax, [portValue]
    call PrintNumber
    call NewLine

    lea dx, fwServiceLabel
    call PrintString
    call PrintServiceName

    lea dx, fwRuleLabel
    call PrintString
    cmp byte ptr [fwFound], 1
    jne fw_unknown_rule
    cmp byte ptr [fwAction], 1
    jne fw_print_block
    lea dx, allowMsg
    call PrintString
    jmp fw_show_risk
fw_print_block:
    lea dx, blockMsg
    call PrintString
    jmp fw_show_risk

fw_unknown_rule:
    lea dx, blockMsg
    call PrintString
    lea dx, unknownRuleMsg
    call PrintString

fw_show_risk:
    lea dx, fwRiskLabel
    call PrintString
    mov al, [fwRisk]
    cmp al, 1
    je fw_low
    cmp al, 2
    je fw_medium
    lea dx, highMsg
    call PrintString
    jmp fw_decision
fw_low:
    lea dx, lowMsg
    call PrintString
    jmp fw_decision
fw_medium:
    lea dx, medMsg
    call PrintString

fw_decision:
    lea dx, fwDecisionLabel
    call PrintString
    cmp byte ptr [fwAction], 1
    jne fw_blocked
    lea dx, allowedDecision
    call PrintString
    ret
fw_blocked:
    lea dx, blockedDecision
    call PrintString
    ret
FirewallSimulator endp

; Prints common service name based on current protocolValue + portValue.
PrintServiceName proc near
    mov ax, [portValue]

    cmp byte ptr [protocolValue], 1
    jne psn_udp

    cmp ax, 21
    je psn_ftp
    cmp ax, 22
    je psn_ssh
    cmp ax, 23
    je psn_telnet
    cmp ax, 25
    je psn_smtp
    cmp ax, 80
    je psn_http
    cmp ax, 443
    je psn_https
    cmp ax, 445
    je psn_smb
    cmp ax, 3389
    je psn_rdp
    cmp ax, 8080
    je psn_httpalt
    jmp psn_unknown

psn_udp:
    cmp ax, 53
    je psn_dns
    cmp ax, 123
    je psn_ntp
    cmp ax, 161
    je psn_snmp
    jmp psn_unknown

psn_ftp:
    lea dx, svcFTP
    call PrintString
    ret
psn_ssh:
    lea dx, svcSSH
    call PrintString
    ret
psn_telnet:
    lea dx, svcTELNET
    call PrintString
    ret
psn_smtp:
    lea dx, svcSMTP
    call PrintString
    ret
psn_dns:
    lea dx, svcDNS
    call PrintString
    ret
psn_http:
    lea dx, svcHTTP
    call PrintString
    ret
psn_ntp:
    lea dx, svcNTP
    call PrintString
    ret
psn_snmp:
    lea dx, svcSNMP
    call PrintString
    ret
psn_https:
    lea dx, svcHTTPS
    call PrintString
    ret
psn_smb:
    lea dx, svcSMB
    call PrintString
    ret
psn_rdp:
    lea dx, svcRDP
    call PrintString
    ret
psn_httpalt:
    lea dx, svcHTTPALT
    call PrintString
    ret
psn_unknown:
    lea dx, unknownService
    call PrintString
    ret
PrintServiceName endp

; ===========================================================================
; FEATURE 3: XOR TEXT ENCRYPTION & DECRYPTION SYSTEM
; Encryption and decryption are one complete cryptography feature.
; ===========================================================================
CryptoSystem proc near
crypto_menu:
    lea dx, cryptoTitle
    call PrintString
    lea dx, cryptoHead
    call PrintString
    lea dx, menuLine
    call PrintString
    lea dx, cryptoMenu1
    call PrintString
    lea dx, cryptoMenu2
    call PrintString
    lea dx, cryptoMenu3
    call PrintString
    lea dx, cryptoPrompt
    call PrintString
    call ReadSingleKey

    cmp al, '1'
    je crypto_encrypt
    cmp al, '2'
    je crypto_decrypt
    cmp al, '3'
    je crypto_return

    lea dx, invalidChoice
    call PrintString
    call PauseForEnter
    jmp crypto_menu

crypto_encrypt:
    call EncryptMessage
    call PauseForEnter
    jmp crypto_menu

crypto_decrypt:
    call DecryptMessage
    call PauseForEnter
    jmp crypto_menu

crypto_return:
    ret
CryptoSystem endp

EncryptMessage proc near
    lea dx, msgPrompt
    call PrintString
    lea di, messageBuf
    mov cx, 80
    call ReadLineEcho
    mov [messageLen], bl

enc_read_key:
    lea dx, keyPrompt
    call PrintString
    lea di, keyBuf
    mov cx, 1
    call ReadLineEcho
    cmp bx, 1
    jne enc_invalid_key
    mov al, [keyBuf]
    cmp al, '1'
    jb enc_invalid_key
    cmp al, '9'
    ja enc_invalid_key
    sub al, '0'
    mov [storedKey], al
    jmp enc_process

enc_invalid_key:
    lea dx, invalidKey
    call PrintString
    jmp enc_read_key

enc_process:
    lea si, messageBuf
    lea di, encryptedBuf
    xor cx, cx
    mov cl, [messageLen]
    jcxz enc_finished

enc_loop:
    mov al, [si]
    xor al, [storedKey]
    mov [di], al
    inc si
    inc di
    loop enc_loop

enc_finished:
    mov byte ptr [hasEncrypted], 1
    lea dx, encryptSuccess
    call PrintString
    lea dx, cipherLabel
    call PrintString

    lea si, encryptedBuf
    xor cx, cx
    mov cl, [messageLen]
    jcxz enc_print_done

enc_print_loop:
    mov al, [si]
    call PrintHexByte
    mov dl, ' '
    call PrintChar
    inc si
    loop enc_print_loop

enc_print_done:
    call NewLine
    ret
EncryptMessage endp

DecryptMessage proc near
    cmp byte ptr [hasEncrypted], 1
    je dec_ready
    lea dx, noEncrypted
    call PrintString
    ret

dec_ready:
    lea dx, decKeyPrompt
    call PrintString
    lea di, keyBuf
    mov cx, 1
    call ReadLineEcho
    cmp bx, 1
    jne dec_invalid_key
    mov al, [keyBuf]
    cmp al, '1'
    jb dec_invalid_key
    cmp al, '9'
    ja dec_invalid_key
    sub al, '0'
    cmp al, [storedKey]
    jne dec_wrong_key
    mov dl, al                    ; DL = validated key
    jmp dec_process

dec_invalid_key:
    lea dx, invalidKey
    call PrintString
    ret

dec_wrong_key:
    lea dx, wrongKey
    call PrintString
    ret

dec_process:
    lea si, encryptedBuf
    lea di, decryptedBuf
    xor cx, cx
    mov cl, [messageLen]
    jcxz dec_finished

dec_loop:
    mov al, [si]
    xor al, dl
    mov [di], al
    inc si
    inc di
    loop dec_loop

dec_finished:
    mov byte ptr [di], 0
    lea dx, decryptSuccess
    call PrintString
    lea dx, plainLabel
    call PrintString

    lea si, decryptedBuf
    xor cx, cx
    mov cl, [messageLen]
    call PrintBuffer
    call NewLine
    ret
DecryptMessage endp

; ===========================================================================
; FEATURE 4: SIGNATURE-BASED THREAT SCANNER
; Searches user text for six predefined signatures using case-insensitive
; substring matching. Reports unique signature count and threat level.
; ===========================================================================
ThreatScanner proc near
    lea dx, scanTitle
    call PrintString
    lea dx, scanHead
    call PrintString
    lea dx, menuLine
    call PrintString
    lea dx, scanPrompt
    call PrintString

    lea di, scanBuf
    mov cx, 100
    call ReadLineEcho              ; BX = input length
    mov byte ptr [foundCount], 0

    lea dx, scanWorking
    call PrintString
    lea dx, scanFoundHeader
    call PrintString

    ; VIRUS
    push bx
    lea si, scanBuf
    mov cx, bx
    lea di, sigVirus
    mov bl, 5
    call ContainsCI
    pop bx
    cmp al, 1
    jne ts_trojan
    inc byte ptr [foundCount]
    lea dx, scanPrefix
    call PrintString
    lea dx, scanVirusMsg
    call PrintString

ts_trojan:
    push bx
    lea si, scanBuf
    mov cx, bx
    lea di, sigTrojan
    mov bl, 6
    call ContainsCI
    pop bx
    cmp al, 1
    jne ts_malware
    inc byte ptr [foundCount]
    lea dx, scanPrefix
    call PrintString
    lea dx, scanTrojanMsg
    call PrintString

ts_malware:
    push bx
    lea si, scanBuf
    mov cx, bx
    lea di, sigMalware
    mov bl, 7
    call ContainsCI
    pop bx
    cmp al, 1
    jne ts_keylogger
    inc byte ptr [foundCount]
    lea dx, scanPrefix
    call PrintString
    lea dx, scanMalwareMsg
    call PrintString

ts_keylogger:
    push bx
    lea si, scanBuf
    mov cx, bx
    lea di, sigKeylogger
    mov bl, 9
    call ContainsCI
    pop bx
    cmp al, 1
    jne ts_ransomware
    inc byte ptr [foundCount]
    lea dx, scanPrefix
    call PrintString
    lea dx, scanKeyloggerMsg
    call PrintString

ts_ransomware:
    push bx
    lea si, scanBuf
    mov cx, bx
    lea di, sigRansomware
    mov bl, 10
    call ContainsCI
    pop bx
    cmp al, 1
    jne ts_exploit
    inc byte ptr [foundCount]
    lea dx, scanPrefix
    call PrintString
    lea dx, scanRansomwareMsg
    call PrintString

ts_exploit:
    push bx
    lea si, scanBuf
    mov cx, bx
    lea di, sigExploit
    mov bl, 7
    call ContainsCI
    pop bx
    cmp al, 1
    jne ts_summary
    inc byte ptr [foundCount]
    lea dx, scanPrefix
    call PrintString
    lea dx, scanExploitMsg
    call PrintString

ts_summary:
    cmp byte ptr [foundCount], 0
    jne ts_count
    lea dx, scanNone
    call PrintString

ts_count:
    lea dx, matchCountLabel
    call PrintString
    mov al, [foundCount]
    xor ah, ah
    call PrintNumber
    call NewLine

    lea dx, threatLevelLabel
    call PrintString
    mov al, [foundCount]
    cmp al, 0
    je ts_safe
    cmp al, 1
    je ts_medium

    lea dx, threatHigh
    call PrintString
    lea dx, threatHighInfo
    call PrintString
    ret

ts_safe:
    lea dx, threatSafe
    call PrintString
    lea dx, threatSafeInfo
    call PrintString
    ret

ts_medium:
    lea dx, threatMedium
    call PrintString
    lea dx, threatMediumInfo
    call PrintString
    ret
ThreatScanner endp

; ===========================================================================
; THREAT-SCANNER HELPER: CASE-INSENSITIVE SUBSTRING SEARCH
; IN : SI = haystack address
;      CX = haystack length
;      DI = needle address
;      BL = needle length
; OUT: AL = 1 if found, AL = 0 if not found
; ===========================================================================
ContainsCI proc near
    push bx
    push cx
    push dx
    push si
    push di
    push bp

    xor bh, bh
    cmp cx, bx
    jb cci_not_found

    mov bp, cx
    sub bp, bx
    inc bp                         ; number of possible starting positions

cci_outer:
    push si
    push di
    xor ch, ch
    mov cl, bl

cci_inner:
    mov al, [si]
    call ToLowerAL
    mov dh, al

    mov al, [di]
    call ToLowerAL
    cmp dh, al
    jne cci_mismatch

    inc si
    inc di
    loop cci_inner

    pop di
    pop si
    mov al, 1
    jmp cci_done

cci_mismatch:
    pop di
    pop si
    inc si
    dec bp
    jnz cci_outer

cci_not_found:
    xor al, al

cci_done:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    ret
ContainsCI endp

; Converts AL from ASCII uppercase to lowercase. Other characters unchanged.
ToLowerAL proc near
    cmp al, 'A'
    jb tla_done
    cmp al, 'Z'
    ja tla_done
    add al, 20h

tla_done:
    ret
ToLowerAL endp

; ===========================================================================
; MAIN MENU / INPUT HELPERS
; ===========================================================================
ShowMainMenu proc near
    lea dx, menuTitle
    call PrintString
    lea dx, menuHead
    call PrintString
    lea dx, menuLine
    call PrintString
    lea dx, menu1
    call PrintString
    lea dx, menu2
    call PrintString
    lea dx, menu3
    call PrintString
    lea dx, menu4
    call PrintString
    lea dx, menu5
    call PrintString
    lea dx, menuPrompt
    call PrintString
    ret
ShowMainMenu endp

; Reads a single visible character followed by ENTER.
ReadSingleKey proc near
    lea di, menuBuf
    mov cx, 1
    call ReadLineEcho
    cmp bx, 1
    jne rsk_empty
    mov al, [menuBuf]
    ret
rsk_empty:
    xor al, al
    ret
ReadSingleKey endp

; ReadLineEcho
; IN : DI = destination buffer, CX = max chars
; OUT: BX = entered length, zero terminator written after input
; Uses DOS AH=08h so backspace and length limiting are controlled manually.
ReadLineEcho proc near
    push ax
    push dx
    xor bx, bx

rle_loop:
    mov ah, 08h
    int 21h

    cmp al, 13
    je rle_done
    cmp al, 8
    je rle_backspace

    cmp bx, cx
    jae rle_loop

    mov [bx+di], al
    inc bx

    mov dl, al
    mov ah, 02h
    int 21h
    jmp rle_loop

rle_backspace:
    cmp bx, 0
    je rle_loop
    dec bx
    mov byte ptr [bx+di], 0

    mov dl, 8
    mov ah, 02h
    int 21h
    mov dl, ' '
    int 21h
    mov dl, 8
    int 21h
    jmp rle_loop

rle_done:
    mov byte ptr [bx+di], 0
    call NewLine
    pop dx
    pop ax
    ret
ReadLineEcho endp

PauseForEnter proc near
    lea dx, pressEnter
    call PrintString
pause_loop:
    mov ah, 08h
    int 21h
    cmp al, 13
    jne pause_loop
    call NewLine
    ret
PauseForEnter endp

; ===========================================================================
; NUMERIC PARSER
; ParseUnsigned16
; IN : SI = digit string, BX = length
; OUT: AX = parsed unsigned number, CF=0 valid / CF=1 invalid or overflow
; ===========================================================================
ParseUnsigned16 proc near
    push bx
    push cx
    push dx
    push si
    push bp

    cmp bx, 0
    je pu_invalid
    cmp bx, 5
    ja pu_invalid

    mov cx, bx
    xor ax, ax
    mov bp, 10

pu_loop:
    mov dl, [si]
    cmp dl, '0'
    jb pu_invalid
    cmp dl, '9'
    ja pu_invalid
    sub dl, '0'
    xor dh, dh
    push dx                       ; preserve current digit

    xor dx, dx
    mul bp                        ; DX:AX = AX * 10
    cmp dx, 0
    jne pu_overflow_pop

    pop dx
    add ax, dx
    jc pu_invalid

    inc si
    loop pu_loop

    clc
    jmp pu_done

pu_overflow_pop:
    pop dx

pu_invalid:
    stc

pu_done:
    pop bp
    pop si
    pop dx
    pop cx
    pop bx
    ret
ParseUnsigned16 endp

; ===========================================================================
; DISPLAY HELPERS
; ===========================================================================
PrintString proc near
    push ax
    mov ah, 09h
    int 21h
    pop ax
    ret
PrintString endp

PrintChar proc near
    push ax
    mov ah, 02h
    int 21h
    pop ax
    ret
PrintChar endp

NewLine proc near
    push dx
    lea dx, crlf
    call PrintString
    pop dx
    ret
NewLine endp

PrintYesNo proc near
    cmp al, 1
    jne pyn_no
    lea dx, yesMsg
    call PrintString
    ret
pyn_no:
    lea dx, noMsg
    call PrintString
    ret
PrintYesNo endp

; PrintBuffer: SI = data address, CX = exact length.
PrintBuffer proc near
    push ax
    push dx
    push si
    push cx
    jcxz pb_done
pb_loop:
    mov dl, [si]
    mov ah, 02h
    int 21h
    inc si
    loop pb_loop
pb_done:
    pop cx
    pop si
    pop dx
    pop ax
    ret
PrintBuffer endp

; PrintNumber: AX = unsigned 16-bit integer.
PrintNumber proc near
    push ax
    push bx
    push cx
    push dx

    cmp ax, 0
    jne pn_convert
    mov dl, '0'
    mov ah, 02h
    int 21h
    jmp pn_done

pn_convert:
    xor cx, cx
    mov bx, 10

pn_divide:
    xor dx, dx
    div bx
    push dx
    inc cx
    cmp ax, 0
    jne pn_divide

pn_print:
    pop dx
    add dl, '0'
    mov ah, 02h
    int 21h
    loop pn_print

pn_done:
    pop dx
    pop cx
    pop bx
    pop ax
    ret
PrintNumber endp

; PrintHexByte: AL = byte, output as two uppercase hexadecimal characters.
PrintHexByte proc near
    push ax
    push bx
    push dx

    mov bl, al

    mov al, bl
    shr al, 1
    shr al, 1
    shr al, 1
    shr al, 1
    and al, 0Fh
    call PrintHexNibble

    mov al, bl
    and al, 0Fh
    call PrintHexNibble

    pop dx
    pop bx
    pop ax
    ret
PrintHexByte endp

PrintHexNibble proc near
    push ax
    push dx
    cmp al, 9
    jbe phn_digit
    add al, 7
phn_digit:
    add al, '0'
    mov dl, al
    mov ah, 02h
    int 21h
    pop dx
    pop ax
    ret
PrintHexNibble endp

end start
