---
title: "Malware Detection & Signature Analysis using YARA & ClamAV"
date: 2026-05-30 00:00:00 +0700
categories: [SOC Report, Malware Analysis, Threat Hunting]
---

## Executive Summary
This report details the technical processes and findings from a comprehensive Malware Analysis Lab focused on utilizing **YARA** and **ClamAV** for threat detection. The primary objectives included analyzing ClamAV database signatures (`.ndb`), extracting and decoding hex/assembly patterns, engineering custom detection rules, and deploying YARA rules to identify specific adversarial behaviors such as process injection, keylogging, and extension spoofing. The findings emphasize the efficacy of signature-based and heuristic-based detection mechanisms in a Security Operations Center (SOC) environment.

## 1. Environment Preparation & Baseline Setup


The analysis environment was initialized by updating the ClamAV virus database using the command `sudo freshclam`, ensuring the detection engine possessed the latest threat signatures.

![pic1](/assets/img/posts/Yara_ClamAV/pic1.png)
![pic2](/assets/img/posts/Yara_ClamAV/pic2.png)
*Figure 1 & 2: ClamAV database update sequence.*

To simulate a malware encounter, several text files containing simulated malicious strings were generated.

![pic3](/assets/img/posts/Yara_ClamAV/pic3.png)
![pic4](/assets/img/posts/Yara_ClamAV/pic4.png)

A preliminary inspection of the simulated files was conducted using the `xxd` utility.

![pic5](/assets/img/posts/Yara_ClamAV/pic5.png)

> [!TIP]
> The `xxd` utility is highly effective for examining the **raw hex content** of a file. It is a critical tool for detecting hidden characters, crafting antivirus signatures, and conducting deep forensic analysis.

<br>

## 2. ClamAV Database Analysis & Signature Reverse Engineering


### Signature Identification
The ClamAV database was queried to identify specific detection rules. A targeted directory containing malware samples was scanned using `clamscan` to observe the triggered signatures.

![pic6](/assets/img/posts/Yara_ClamAV/pic6.png)
![pic7](/assets/img/posts/Yara_ClamAV/pic7.png)
![pic8](/assets/img/posts/Yara_ClamAV/pic8.png)

The scan successfully triggered the signature **`Win.Packed.Malwarex-10059342-0`**. Further investigation located this signature within the `daily.ldb` database file.

![pic9](/assets/img/posts/Yara_ClamAV/pic9.png)

### Hex to Assembly Decoding
The extracted signature contained raw bytecode. To interpret this machine code, the `ndisasm` disassembler was employed to translate the hex into readable **Assembly (ASM)** instructions.

![pic10](/assets/img/posts/Yara_ClamAV/pic10.png)
![pic11](/assets/img/posts/Yara_ClamAV/pic11.png)

**Behavioral Analysis of the Disassembled Code:**
The identified ASM instructions are characteristic of a **Malware Packer/Stub**. The primary function of this stub is to self-decrypt and unpack the malicious payload into memory, thereby evading static AV detection.

*   `insd`, `pusha`: Retrieves the execution address and preserves the state of CPU registers prior to decryption.
*   `cs pop ecx`: Executes a memory context switch to access the packed data.
*   `sub ah, [eax+0x45]`, `das`: The core decryption routine (often utilizing subtraction or XOR operations) designed to restore the original machine code from the obfuscated data.

> [!IMPORTANT]
> This stub acts as a protective shell, allowing the malware to remain dormant and encrypted on the disk, only revealing its true malicious form during in-memory execution.

<br>

## 3. Custom Signature Engineering & Deployment


A custom signature database (`mywildcard.ndb`) was engineered using the standard format: `Malware_Name:Target:Offset:Hex_String`.

![pic12](/assets/img/posts/Yara_ClamAV/pic12.png)

The creation of custom `.ndb` files serves three strategic purposes:
1.  **Zero-Day Detection:** Provides ClamAV with indicators of compromise (IoCs) for novel malware not yet present in the global database.
2.  **Proactive Triage:** Enables the definition of localized, environment-specific scanning rules.
3.  **Structural Research:** Facilitates a deeper understanding of how ClamAV parses and matches logical signatures.

A validation scan was executed using the custom database: `clamscan -d mywildcard.ndb test1.txt test2.txt test3.txt test4.txt test5.txt`

![pic13](/assets/img/posts/Yara_ClamAV/pic13.png)

The results confirmed the successful loading, compilation, and execution of the custom rules, triggering `.UNOFFICIAL` alerts on the test files.

### In-Depth Signature Analysis (ASCII & Bytecode)

Eight sample signatures were extracted from `main.ndb` and `daily.ndb` for deeper forensic analysis.

#### A. ASCII String Extraction
The first four signatures were parsed for readable ASCII content.

![pic14](/assets/img/posts/Yara_ClamAV/pic14.png)

**1. `main.ndb:Doc.Trojan.Nori-1`**
![pic15](/assets/img/posts/Yara_ClamAV/pic15.png)
*   **Analysis:** Contains strings like `CodeModule.Lines`, `Components.Item`, and `<> "'Iron" Then`.
*   **Conclusion:** This signature targets malicious **VBA macros** embedded in Microsoft Office documents. The strings suggest self-modifying code or logic designed to inspect the VBA project structure, a common tactic for evading detection or hiding malicious logic.

**2. `main.ndb:Win.Trojan.Dialer-1`**
![pic16](/assets/img/posts/Yara_ClamAV/pic16.png)
*   **Analysis:** Reveals fragments like `http://...`, `.exe`, `Software\Web...`, and `Passw...`.
*   **Conclusion:** Indicates behavior associated with payload downloading (HTTP/EXE), persistent configuration via the Windows Registry (`Software\...`), and potential credential theft (`Passw...`).

**3. `main.ndb:Win.Trojan.GWGirl-1`**
![pic17](/assets/img/posts/Yara_ClamAV/pic17.png)
*   **Analysis:** Decodes to `.com`, `DXInput.dll`, `G2h7o2st_Event`, and `\SCANREGW.EXE`.
*   **Conclusion:** Targets suspicious DLL loading (`DXInput.dll`), specific synchronization objects/mutexes (`G2h7o2st_Event`), and potential masquerading using legacy Windows system files (`SCANREGW.EXE`).

**4. `main.ndb:Win.Trojan.DeltaV1-1`**
![pic18](/assets/img/posts/Yara_ClamAV/pic18.png)
*   **Analysis:** Extracts `.com`, `Delta v1.0 by Retro`, and `http:/`.
*   **Conclusion:** Identifies a likely legacy virus targeting `.com` executables, characterized by a specific author/tool artifact (`Delta v1.0 by Retro`).

#### B. Bytecode (Assembly) Decoding
The remaining four signatures were decoded using `ndisasm` to analyze the underlying operational logic.

![pic19](/assets/img/posts/Yara_ClamAV/pic19.png)

**1. `Win.Worm.Gaobot-1`**
![pic20](/assets/img/posts/Yara_ClamAV/pic20.png)
*   **Analysis:** Contains direct register manipulation (`xor al,0x67`, `and`, `or`) and conditional branching (`jz`, `jnc`, `jnz`).
*   **Conclusion:** The signature targets specific byte-level logic and conditional execution flows, indicative of obfuscated or structurally unique machine code rather than simple string matching.

**2. `Win.Worm.Bormex-1`**
![pic21](/assets/img/posts/Yara_ClamAV/pic21.png)
*   **Analysis:** Shows intensive register operations (`inc`, `adc`, `add`, `xor`), stack manipulation (`push`), and conditional loops (`loopne`).
*   **Conclusion:** Represents a complex byte pattern designed to detect intricate data processing or highly obfuscated routines.

**3. `Vbs.Tool.Svbsvc-1`**
![pic22](/assets/img/posts/Yara_ClamAV/pic22.png)
*   **Analysis:** Features data comparison (`cmp`), various conditional jumps (`jg`, `jz`, `jno`), and low-level I/O operations (`outsb`, `insd`).
*   **Conclusion:** Targets structural branching and low-level system interaction patterns.

**4. `Win.Ircbot.Netol-1`**
![pic23](/assets/img/posts/Yara_ClamAV/pic23.png)
*   **Analysis:** When properly interpreted as UTF-16LE, it reveals `elseif  ($exists(c:\netol.scr`. (Initially misinterpreted by ndisasm).
*   **Conclusion:** This signature is designed to detect a script checking for the existence of `c:\netol.scr`. The `.scr` (screensaver) extension is frequently abused to mask executable malware payloads.

<br>

## 4. YARA Rule Development & Threat Hunting


YARA (v4.5.5) was deployed and utilized to hunt for specific behavioral indicators across a repository of known malware samples (The Zoo).

![pic25](/assets/img/posts/Yara_ClamAV/pic25.png)
![pic26](/assets/img/posts/Yara_ClamAV/pic26.png)

A comprehensive ruleset comprising 10 distinct YARA rules was engineered to detect various malicious capabilities:

1.  **PE File Identification:** Targets the `MZ` magic bytes and `PE` header. (Fig. 27)
2.  **Keylogger APIs:** Detects combinations of keystroke logging and window tracking APIs. (Fig. 28)
3.  **Process Injection APIs:** Identifies memory allocation, remote thread creation, and process manipulation functions. (Fig. 29)
4.  **Network Communication APIs:** Flags HTTP requests and payload download mechanisms. (Fig. 30)
5.  **System Command Execution:** Searches for `cmd.exe`, `powershell`, and `ShellExecute`. (Fig. 31)
6.  **Registry Persistence:** Identifies modifications to autorun keys (`Run`, `HKCU`, `HKLM`). (Fig. 32)
7.  **High Entropy (Packed) PEs:** Detects executables with entropy > 7.2, indicating packing or encryption. (Fig. 33)
8.  **Suspicious File Extensions:** Flags commonly abused extensions like `.scr`, `.vbs`, and `.ps1`. (Fig. 34)
9.  **Mutex/Event Objects:** Detects `CreateMutex` or specific event string patterns used for infection marking. (Fig. 35)
10. **Embedded PE Files:** Identifies files where a PE header exists, but the `MZ` signature is not at offset 0, indicating a dropped or embedded payload. (Fig. 36)

![pic27](/assets/img/posts/Yara_ClamAV/pic27.png)
![pic28](/assets/img/posts/Yara_ClamAV/pic28.png)
![pic29](/assets/img/posts/Yara_ClamAV/pic29.png)
![pic30](/assets/img/posts/Yara_ClamAV/pic30.png)
![pic31](/assets/img/posts/Yara_ClamAV/pic31.png)
![pic32](/assets/img/posts/Yara_ClamAV/pic32.png)
![pic33](/assets/img/posts/Yara_ClamAV/pic33.png)
![pic34](/assets/img/posts/Yara_ClamAV/pic34.png)
![pic35](/assets/img/posts/Yara_ClamAV/pic35.png)
![pic36](/assets/img/posts/Yara_ClamAV/pic36.png)

<br>

### YARA Execution Results
The ruleset was executed against the `theZoo` repository: `yara -r custom_rules.yar theZoo`

![pic37](/assets/img/posts/Yara_ClamAV/pic37.png)

**Key Findings from YARA Scan:**
*   **Rule_05 (Command Execution) & Rule_08 (Suspicious Extensions):** Triggered heavily across families like WannaCry, Zeus, AsyncRAT, and QuasarRAT, confirming their reliance on scripts and shell commands.
*   **Rule_10 (Embedded PE):** Successfully detected `Android.CEREBRUS 2.zip.001/.002`, indicating the presence of embedded executables within the archive fragments.
*   **Rule_06 (Registry Persistence):** Flagged objects within the `.git` directory. This is noted as a **false positive** caused by scanning version control history containing registry-related strings.

<br>

## 5. Practical Use Case: Detecting Extension Spoofing


A practical scenario was simulated involving **Extension Spoofing**, where an executable file is disguised as a benign text document.

A malicious file named `invoice.txt` was created, but its internal header began with `4D 5A` (the MZ magic bytes of a PE file).

![pic38](/assets/img/posts/Yara_ClamAV/pic38.png)

A specific YARA rule was crafted to detect this evasion technique:

![pic39](/assets/img/posts/Yara_ClamAV/pic39.png)

**Rule Logic:** The rule verifies if the `MZ` signature exists exactly at offset 0, AND the `PE` string is present, but the file extension (in a real-world scenario, evaluated by the scanning engine or analyst) does not match its internal structure.

The rule successfully identified the spoofed `invoice.txt` file.

![pic40](/assets/img/posts/Yara_ClamAV/pic40.png)

<br>

## 6. Conclusion & SOC Recommendations


**ClamAV** excels at rapid, scalable scanning utilizing vast databases of known signatures (`.ndb`, `.ldb`). It is highly effective for identifying known threats but is susceptible to evasion techniques such as polymorphism, packing, and string obfuscation due to its reliance on static pattern matching.

**YARA** provides a highly flexible and powerful framework for threat hunting and static analysis. It empowers analysts to construct complex, logic-based rules targeting specific behaviors, APIs, entropy levels, and structural anomalies (like extension spoofing). However, poorly tuned YARA rules can lead to high false-positive rates (as seen with the `.git` directory scan).

**Recommendation:** For robust SOC operations, signature-based engines (ClamAV) should be utilized for initial triage and known-threat mitigation, while behavioral and heuristic-based engines (YARA) must be deployed for advanced threat hunting, detecting novel evasion techniques, and analyzing polymorphic malware families. Neither should act as a standalone solution; they must be integrated with dynamic analysis (sandboxing) and Endpoint Detection and Response (EDR) telemetry.