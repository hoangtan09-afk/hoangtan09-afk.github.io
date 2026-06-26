---
title: "Detecting Malware with YARA & ClamAV"
date: 2026-05-30 00:00:00 +07000
categories: [Malware Analysis]

---

Hello everyone, today we will get acquainted with the Malware Analysis Lab. Specifically, we will focus on malware detection using Yara rules & ClamAV. Let's get started.

<br>

**1. Installation & Sample Preparation**
 
![pic1](/assets/img/posts/Yara_ClamAV/pic1.png)

Since I had already installed ClamAV, I only needed to run the command `sudo freshclam` to update the virus database for ClamAV.

![pic2](/assets/img/posts/Yara_ClamAV/pic2.png)
 


Proceed to create text files containing simulated malware strings.

![pic3](/assets/img/posts/Yara_ClamAV/pic3.png)
![pic4](/assets/img/posts/Yara_ClamAV/pic4.png)
 

View the hex code of the file using `xxd`.

![pic5](/assets/img/posts/Yara_ClamAV/pic5.png)
 

`xxd` helps view the **actual content** of a file in hex format — highly useful for detecting hidden characters, writing antivirus signatures, and forensic analysis.

**2. Dissecting the ClamAV Database**

Extraction & Location & Decompilation
 
![pic6](/assets/img/posts/Yara_ClamAV/pic6.png)
![pic7](/assets/img/posts/Yara_ClamAV/pic7.png)
 

I had already extracted it beforehand. I will proceed to find the rule in the database as follows. To do that, I will first **clamscan** a folder containing **malware** to see which rule is returned in the results:
 
![pic8](/assets/img/posts/Yara_ClamAV/pic8.png)

I successfully scanned and found **Win.Packed.Malwarex-10059342-0**.

Proceed to find this rule in the database.

![pic9](/assets/img/posts/Yara_ClamAV/pic9.png)
 
I found this rule located inside the **daily.ldb** file.

Decompiling Hex to ASCII

![pic10](/assets/img/posts/Yara_ClamAV/pic10.png)
 
It seems this is byte code (machine code), resulting in characters we cannot read yet. I will use **ndisasm** to disassemble it into **Assembly**.

![pic11](/assets/img/posts/Yara_ClamAV/pic11.png)
 
After researching online for a while, I understood the **functionality** of these **Assembly** segments. Specifically:

These **Assembly** lines belong to the **Packer/Stub** (bootstrap code) of the malware. The main purpose is **self-decoding** to unpack the malicious body into memory to evade AV detection.

**Summary of commands:**
-	**insd, pusha:** Used to get the execution address and preserve register states before decryption.
-	**cs pop ecx:** A memory context switching technique to access compressed data.
-	**sub ah, [eax+0x45], das:** This is the decryption algorithm (often subtraction or XOR) to restore the original machine code from the obfuscated data.

In other words: This is a "protective shell" that helps the malware hide while on the hard drive and only reveal itself when executed in memory.


**3. Creating Custom Signatures**

Create the `mywildcard.ndb` file using the syntax: `Malware_Name:Target:Offset:Hex_String`

![pic12](/assets/img/posts/Yara_ClamAV/pic12.png)
 

**Creating the .ndb file serves 3 main purposes:**

**1. Detecting new malware:** Providing ClamAV with the "signature" of a new malware type that the system's default database does not yet have.

**2. Proactive control:** Allowing me to define separate custom scan rules to detect suspicious files in the Lab environment without affecting the system database.

**3. Studying the structure:** Helping me understand how ClamAV analyzes and matches malware based on Hex strings or logical rules (Logical Signatures).

Proceed to perform a test scan with the newly created database using the command:

**clamscan -d mywildcard.ndb test1.txt test2.txt test3.txt test4.txt test5.txt**

![pic13](/assets/img/posts/Yara_ClamAV/pic13.png)

Based on the results, the custom database I created successfully scanned the 5 simulated text files generated at the beginning of the lab.

This means **ClamAV** has successfully:

-	Successfully loaded the `mywildcard.ndb` database
-	Compiled all 6/6 signatures
-	Scanned the test files
-	Detected files matching the custom signatures I wrote
-	The `.UNOFFICIAL` suffix is normal, as this is a **custom signature** I created, not an official signature from ClamAV.

Now I will extract 08 signature samples from the ClamAV database for analysis:

**- First 4 samples:** I will use `xxd` to translate Hex to ASCII.

**- Last 4 samples:** I will use `ndisasm` to disassemble Hex into Bytecode (Assembly), then use AI to analyze the behavior.

<br>
<br>

<span style="font-size: 16px; color: #87CEEB">**Translate to ASCII**</span>
<br>

I run the following command to extract the **first 04 samples** from **main.ndb** and **daily.ndb** first:

**grep -E '^[^:]+:[0-9]+:[^:]+:[0-9A-Fa-f]+$' main.ndb daily.ndb \ | grep -iE '68747470|2e657865|2e646c6c|6d6163726f|736372697074|766273|706f7765727368656c6c|636d642e657865|4d6963726f736f6674|436f64654d6f64756c65' \ | head -n 4 > ascii_4.txt**

The command I run prioritizes filtering signatures that can be translated into ASCII without displaying machine code.

![pic14](/assets/img/posts/Yara_ClamAV/pic14.png)
 
Now I proceed to translate to ASCII for each type:

<br>

**main.ndb:Doc.Trojan.Nori-1**

![pic15](/assets/img/posts/Yara_ClamAV/pic15.png)
 
**Meaning of this signature:**

Through my investigation, I believe this appears to be **a VBA macro code segment in a malicious Office document**. Main indicators:

- **CodeModule.Lines(2, 1):** accesses code lines in the VBA module.

- **Components.Item(...):** manipulates components/macros inside the VBA project.

- **<> "'Iron" Then:** conditional statement checking if the code line content is different from the string `'Iron`.

This is likely a signature to detect self-checking/self-modifying VBA macro code, commonly found in macro malware used for **hiding code, self-modifying macros, or checking for infection markers.**

<br>

**main.ndb:Win.Trojan.Dialer-1**

![pic16](/assets/img/posts/Yara_ClamAV/pic16.png)
 
**Meaning of this signature:**

I found that this signature has many unreadable bytes, but some notable IOCs/strings are still visible:

- http://...
- .exe
- Software\Web...
- Passw...
- Exit

The presence of `http://...` and `.exe` strings: likely related to **downloading executable files from URLs** or identifying samples with **payload download** behaviors.

`Software\Web...` : suggests relation to a **Registry path or software configuration on Windows**.

`Passw...` : could be related to the string "Password", commonly found in **information-stealing malware**, but this part is noisy so I cannot make a definite conclusion.

Many corrupted/unreadable characters: this is not a pure ASCII string, but a byte pattern used by ClamAV to identify malware.

<br>

**main.ndb:Win.Trojan.GWGirl-1**

![pic17](/assets/img/posts/Yara_ClamAV/pic17.png)
 
**Meaning of this signature:**

Decoded signature:

.com

DXInput.dll

G2h7o2st_Event

\SCANREGW.EXE

-	**.com:** could be related to legacy executable files or a domain, but since it stands alone, I cannot draw a conclusion.
-	**DXInput.dll:** A fake DLL mimicking a system library or game input library, potentially used for masquerading.
-	**G2h7o2st_Event:** A string structured like an event or mutex name, commonly used to identify an instance or synchronize processes.
-	**\SCANREGW.EXE:** A filename resembling the old Windows tool SCANREGW.EXE, which might be abused by malware for masquerading.

Conclusion: This signature shows signs of detecting malware based on suspicious DLLs, event/mutex names, and spoofed system EXE files, but is insufficient to conclude specific behaviors.

<br>

**main.ndb:Win.Trojan.DeltaV1-1**

![pic18](/assets/img/posts/Yara_ClamAV/pic18.png)
 
**Meaning of this signature:**
	This signature decodes to a partially readable string:

**.com**

**Delta v1.0 by Retro**

**http:/**

- 	**"*.com"**: could be related to DOS-style .com executables, or malware samples infecting .com files.
-	**"Delta v1.0 by Retro"**: resembles an identifier string or internal name of the malware or tool left by the author.
-	**http:/**: suggests a URL component, but the string is truncated, making it insufficient to determine the C2 or download link.
-   **The first part** contains many binary bytes and segments resembling DOS/assembly instructions, so this is not pure ASCII but rather a byte pattern for malware detection.

**Conclusion:** This signature is highly likely used to detect a legacy malware/virus sample associated with .com files, containing the identifier string "Delta v1.0 by Retro", but there is insufficient data to conclude specific behavior.
	
<br>

<span style="font-size: 16px; color: #87CEEB">**Translate to Byte Code (Assembly)**</span>

<br>
In the next step, I will extract the remaining **04 signature samples** to translate into byte code using the command:

**grep -h -E '^[^:]+:[0-9]+:[^:]+:[0-9A-Fa-f]+$' main.ndb daily.ndb \ | grep -viE 'trojan|nori|layla' \ | head -n 4 > asm_4.txt**

I use this command to filter out 04 other samples that **do not contain Trojan, and do not contain Nori/Layla**.

![pic19](/assets/img/posts/Yara_ClamAV/pic19.png)


Proceed to disassemble into byte code for each type:

<br>
**Win.Worm.Gaobot-1**
 
![pic20](/assets/img/posts/Yara_ClamAV/pic20.png)

**Meaning of this signature:**

When disassembled into assembly, this signature shows **many direct manipulation commands** with **registers** and **memory areas**, for example:

**xor al,0x67**

**and [edx+0x2ddc0d83],dl**

**mov cl,[eax+0x45907da4]**

**or [ebx+0x73254089],dl**

**jz 0x5a**

**jnc 0x93**

**jnz 0x77**

-	`xor al,0x67`: performs an XOR operation on the AL register, potentially related to data processing/transformation. 
-	Commands like `and`, `or`, `sub`, `cmp`: logical operations and data comparisons in memory. 
-	Jump commands like `jz`, `jnc`, `jnz`: indicate conditional branching in the execution flow. 
-	Some bytes are recognized as separate strings like `.com`, `quit`, `cac`, showing that the signature might be capturing a sample containing both machine code bytes and text strings.

**Brief Conclusion:**

This signature describes a byte pattern containing register manipulation, memory access, and conditional branching instructions. It might be used by **ClamAV** to identify a malware sample based on **byte-level characteristics**, including signs related to `.com` files and disconnected command strings like `quit`.

<br>

**Win.Worm.Bormex-1**

![pic21](/assets/img/posts/Yara_ClamAV/pic21.png)
 
**Meaning of this signature:**

-	**inc ebx, adc, add, xor, sub, and, or**: instructions manipulating data at the **register/memory** level.

-	**push dword [esp+0x8]**: pushes a parameter onto the stack, potentially related to function calls or data processing.

-	**test eax,eax + jz:** checks the result in eax, and branches if it is 0.

-	**jmp word 0x8313:**dword 0xee05a19d: a far jump instruction, commonly seen in complex byte patterns or obfuscated code.

-	**int byte 0x78:** triggers an interrupt, potentially an indicator of low-level code or a special byte sequence.

-	**loopne:** conditional loop, showing the capability to iterate over data.

**Brief Conclusion:**
This signature describes a byte pattern with extensive register, memory, stack manipulations, and conditional branching. It can be used by ClamAV to identify code exhibiting complex data processing or byte-level obfuscation. However, no clear APIs or strings are visible yet, which is insufficient to conclude specific behavior.
	
<br>

**Vbs.Tool.Svbsvc-1**

![pic22](/assets/img/posts/Yara_ClamAV/pic22.png)


**Meaning of this signature:**

When disassembled into assembly, this signature shows many register manipulation, comparison, and branching instructions.

**Key Meanings:**

-	**inc, dec, xor, and, sub, cmp:** instructions for data processing and value comparison.

-	**jg, jz, jno, jnc, jng:** multiple conditional jump instructions, showing that the pattern features branching.

-	**push, pop, popa:** stack and register manipulations.

-	**outsb, insd, insb:** low-level I/O instructions, commonly appearing in byte patterns or specialized machine code.

**Brief Conclusion:**

This signature is a byte pattern with multiple logical, stack, and conditional jump operations. It could be used by ClamAV to identify code that has a complex structure or is modified at the byte level. However, no APIs, URLs, or clear strings are observed, so it is insufficient to infer specific malware behavior.

<br>

**Win.Ircbot.Netol-1**

![pic23](/assets/img/posts/Yara_ClamAV/pic23.png)
 
**Meaning of this signature:**

When decoded, this signature is actually a **Unicode UTF-16LE string**, not pure machine code. Reading it as text, it is roughly:

**elseif  ($exists(c:\netol.scr**

-	**elseif:** conditional syntax, commonly seen in scripts.
-	**$exists(...):** checks for the existence of a file/path. 
-	**c:\netol.scr:** checks for the **.scr** file in the C drive. A **.scr** file is a screensaver, but it is actually a Windows executable, frequently abused by malware to disguise payloads. 

When passed into **ndisasm**, it was erroneously disassembled into commands like:

**add [gs:eax+eax+0x73],ch**

**imul eax,[eax],0x200066**

**cmp al,[eax]**

These commands have no clear behavioral meaning because ndisasm is misinterpreting the UTF-16LE string as assembly.

**Brief Conclusion:**

This signature is highly likely used to detect a script/malware segment checking for the existence of the file **c:\netol.scr**, where **.scr** is a format easily exploited to conceal malicious executables.

<br>

<span style="font-size: 20px; color: #87CEEB">**Part 2: Writing YARA Rules**</span>


<br>
To proceed with writing Yara rules, first I needed to install Yara. I ran the following commands to install it:

**Sudo apt update**

**Sudo apt install git yara -y**
 
I successfully installed Yara, version 4.5.5


![pic25](/assets/img/posts/Yara_ClamAV/pic25.png)


Next, I will clone The Zoo repository to my machine:

**git clone https://github.com/ytisf/theZoo.git**
 
![pic26](/assets/img/posts/Yara_ClamAV/pic26.png)

Next, we come to the important part: writing 10 YARA rules.

<br>

**Rule 1: Identifying PE Files**

![pic27](/assets/img/posts/Yara_ClamAV/pic27.png)
 
**Explanation:**

-	**Function:** Identifies Windows executable files in PE format.

-	**Signatures:** PE files usually start with MZ, with a PE header inside.
-	**Match conditions:** $mz must be at the very beginning of the file (offset 0) and $pe must be present.
-	**Significance:** Used to filter files structured as Windows executables.

<br>

**Rule 2: Identifying Keylogger APIs**

![pic28](/assets/img/posts/Yara_ClamAV/pic28.png)

**Explanation:**

-	**Function:** Detects keylogger indicators.

-	**Signatures:** APIs related to keystroke logging and active window tracking.

-	**Match conditions:** At least 2 out of the 3 API strings must appear.
-	**Significance:** If a file utilizes multiple of these APIs, it likely tracks keystrokes/user activities.

<br>

**Rule 3: Identifying Process Injection APIs**

![pic29](/assets/img/posts/Yara_ClamAV/pic29.png)

 
**Explanation:**

-	**Function:** Detects process injection indicators.

-	**Signatures:** APIs commonly used to open processes, allocate memory, write malicious code into another process, and create remote threads.

-	**Match conditions:** At least 2 APIs must be present.

-	**Significance:** This is a common behavior in malware to hide code inside legitimate processes.

<br>

**Rule 4: Identifying Network Connection APIs**
 
![pic30](/assets/img/posts/Yara_ClamAV/pic30.png)

**Explanation:**

-	**Function:** Detects files with network communication indicators.

-	**Signatures:** APIs used to open Internet connections, send HTTP requests, or download files.

-	**Match conditions:** At least 2 API strings must be present.

-	**Significance:** Could be related to payload downloading, C2 communication, or exfiltrating data.


<br>

**Rule 5: System Command Execution Indicators**
 
![pic31](/assets/img/posts/Yara_ClamAV/pic31.png)

**Explanation:**

- **Function:** Identifies system command execution behavior.

- **Signatures:** cmd.exe, powershell, /c, ShellExecute.

- **Match conditions:** Only one of the strings needs to appear.

- **Significance:** Malware often uses the command line to run scripts, download files, establish persistence, or execute payloads.

<br>

**Rule 6: Identifying Registry Persistence**

![pic32](/assets/img/posts/Yara_ClamAV/pic32.png)
 
**Explanation:**

- **Function:** Detects persistence indicators via the Registry.

- **Signatures:** Registry keys like Run, HKCU, HKLM, or Registry writing APIs.

- **Match conditions:** At least one string must appear.

- **Significance:** Malware can use the Registry to automatically run after the system boots.


<br>

**Rule 7: Identifying High-Entropy, Packed PE Files**

![pic33](/assets/img/posts/Yara_ClamAV/pic33.png)

**Explanation:**

-   **Function:** Identifies PE files likely packed or encrypted.

-	**Signatures:** High file-wide entropy.

-	**Match conditions:** The file must be a PE, size > 50KB, and entropy > 7.2.

-	**Significance:** Packed files typically have high entropy because the data is compressed/encrypted to conceal the real code.


<br>

**Rule 8: Identifying Extensions Often Exploited by Malware**

![pic34](/assets/img/posts/Yara_ClamAV/pic34.png)
 
**Explanation:**

-   **Function:** Identifies file extensions commonly exploited.

-   **Signatures:** .scr, .vbs, .bat, .ps1, .dll.

-   **Match conditions:** At least 2 extensions must appear.

-   **Significance:** Malware may drop or call auxiliary scripts/executable files to execute malicious behaviors.


<br>

**Rule 9: Identifying Mutex or Event Strings**

![pic35](/assets/img/posts/Yara_ClamAV/pic35.png)
 
**Explanation:**

-	**Function:** Detects mutex/event indicators.

-	**Signatures:** Global\, Local\, CreateMutex, _Event.

-	**Match conditions:** Only one string needs to appear.

-	**Significance:** Malware often uses a mutex to prevent running multiple instances simultaneously or to mark the machine as infected.



<br>

**Rule 10: Identifying PE Signatures Where MZ is Not at the File Beginning**

![pic36](/assets/img/posts/Yara_ClamAV/pic36.png)

**Explanation:**

-   **Function:** Identifies files with an embedded PE inside.

-	**Signatures:** MZ and PE are present, but MZ is not at the beginning of the file.

-	**Match conditions:** Both $mz and $pe are present, and $mz is not at offset 0.

-	**Significance:** The file may contain an embedded PE payload, commonly seen in droppers/loaders.

<br>

**The 10 rules I wrote are designed across various behavioral groups: PE identification, keylogger API, process injection, network API, command execution, registry persistence, high-entropy packed files, suspicious extensions, mutex/event, and embedded PE. While no single rule definitively concludes a file is malicious, they help detect suspicious indicators for static analysis.**

<br>

Next, I proceeded to scan the cloned The Zoo directory using the command:

**yara -r custom_rules.yar theZoo**

![pic37](/assets/img/posts/Yara_ClamAV/pic37.png) 
 
As shown in the image above, the rules I wrote matched many malware samples.

Specifically, the output shows that rules such as **Rule_05_Command_Execution, Rule_08_Suspicious_File_Extensions, Rule_10_Dropped_PE_Inside_File, Rule_01_PE_File, and Rule_06_Registry_Persistence** matched many .zip, .pyd, .db files, as well as files in the .git folder of The Zoo.


<br>

**Rule_05_Command_Execution**

This rule matched the most. It detects strings like:

- **cmd.exe**

- **powershell**

- **/c**

- **ShellExecute**

Many malware files in The Zoo contain system command execution indicators, which is why this rule matched numerous samples like **WannaCry_Plus, Petrwrap, Fareit, Zeus, QuasarRAT, PowerLoader**, etc. However, this rule is quite broad and can lead to false positives, as it also matched `theZoo/conf/maldb.db`.


<br>

**Rule_08_Suspicious_File_Extensions**

This rule detects suspicious file extensions like:

- **.scr**

- **.vbs**

- **.bat**

- **.ps1**

- **.dll**

It matched many malware source files such as **njRAT, LokiRAT, AsyncRAT, QuasarRAT, Carberp**, etc. 
This is logical because malware source code often contains scripts, DLLs, or extensions used to drop/execute payloads.


<br>

**Rule_10_Dropped_PE_Inside_File**

This rule matched with:

- **Android.CEREBRUS 2.zip.001**

- **Android.CEREBRUS 2.zip.002**

This rule looks for the presence of **MZ** and **PE** where **MZ** is not at the beginning of the file. This suggests that the file may contain an embedded PE or PE-like data. For the .zip.001/.002 files, it is highly likely that the archives contain a PE payload or a PE-like byte pattern.

<br>

**Rule_01_PE_File**

This rule only matched:

- **theZoo/imports/_rlsetup.pyd**

.pyd is actually a Python extension module on Windows, which typically has a PE structure similar to a .dll. Therefore, matching the PE rule is normal.

<br>

**Rule_06_Registry_Persistence**

This rule matched in:

- **theZoo/.git/objects/pack/...**

This is not a direct malware sample but a Git pack file. This match is likely because the Git object contains source/history content with Registry strings like HKCU, HKLM, or Software\Microsoft\Windows\CurrentVersion\Run. Therefore, this section should be noted as a potential false positive due to scanning the entire .git directory.


<br>

<span style="font-size: 20px; color: #87CEEB">**Part 3: Practical YARA - Unmasking Masquerading Techniques**</span>

<br>

**Choose scenario A (Extension Spoofing - using magic module) or B (.NET Malware - using dotnet module).**

Here, I chose scenario **A Extension Spoofing** to implement.

I will create a spoofed file with a `.txt` extension but containing an EXE header.

![pic38](/assets/img/posts/Yara_ClamAV/pic38.png) 

 
The beginning of the file has `4D 5A`, which is the magic byte number of a PE file.


Now I will write a Yara rule to detect **extension spoofing**:

![pic39](/assets/img/posts/Yara_ClamAV/pic39.png) 
 
This rule is used to detect **extension spoofing**: the file looks like a `.txt` on the outside, but contains indicators of a Windows executable inside.

-	**$mz = { 4D 5A }**: finds the MZ magic bytes. This indicator usually appears at the beginning of Windows .exe files.
-	**$pe = "PE"**: finds the "PE" string, typically found in the PE header of Windows executables.
-	**condition:** $mz at 0 and $pe: the rule only matches when: 

	- **MZ** is located at the very beginning of the file (offset 0); 

	- and the **PE** string is present in the file.


**Significance:**

If a file named `invoice.txt` has content starting with MZ and containing PE, it is not a normal text file. It shows signs of being a Windows executable with a modified extension to deceive the user.

Now I will use this rule to scan the `.txt` file mentioned above:

**yara spoofing_rule.yar invoice.txt**

![pic40](/assets/img/posts/Yara_ClamAV/pic40.png) 
 
**The scan results show that the rule successfully matched the conditions and triggered.**

<br>

<span style="font-size: 20px; color: #87CEEB">**Part 4: Evaluation and Analysis (Discussion)**</span>

<br>

Both **ClamAV** and **YARA** are tools that support signature-based malware detection, but they are used differently. ClamAV is better suited for quick scanning using ready-made databases like **main.ndb, daily.ndb, or custom.ndb**. The advantage of ClamAV is that it is easy to use, comes with a vast database of pre-existing signatures, and requires only running clamscan to detect matching samples. However, ClamAV heavily relies on static signatures, making it easy to evade if the malware alters its byte patterns, packs files, encrypts strings, or obfuscates code.

YARA is more flexible as analysts can write custom rules based on multiple criteria: strings, hex patterns, APIs, PE headers, entropy, sections, or complex logical conditions. YARA is well-suited for static analysis, hunting malware families, and detecting masquerading techniques like extension spoofing. The disadvantage is that if a rule is written too broadly, it causes false positives, whereas if it is too strict, it can easily miss variant samples.

Against polymorphic techniques, packers, and obfuscation, both tools have their limitations. Therefore, results from ClamAV/YARA should only be regarded as initial indicators, necessitating a combination of in-depth static analysis and dynamic analysis for an accurate conclusion.
