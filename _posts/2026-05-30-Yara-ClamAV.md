---
title: "YARA & ClamAV"
date: 2026-05-30 00:00:00 +07000
categories: [Malware Analysis]

---

Hello everyone, today we will get familiar with the Malware Analysis Lab. Specifically, we will focus on detecting malware using YARA rules and ClamAV. Let’s get started.

**1. Installation and preparation of samples**

Because I had already installed ClamAV before, I only needed to run the command `sudo freshclam` to update the virus database for ClamAV.

I then created text files containing simulated malicious strings.

I viewed the hex of the file using `xxd`.

`xxd` helps us see the actual content of a file in hexadecimal format — very useful for detecting hidden characters, writing virus signatures, and performing forensic analysis.

**2. ClamAV database analysis**

Extract & locate & unzip

I had already extracted it earlier. I will continue to search for rules in the database as follows. To do that, first I will **clamscan** a directory containing **malware** to see which rules are returned in the results:

I scanned successfully and found **Win.Packed.Malwarex-10059342-0**.

Then I searched for this rule in the database.

I found that this rule is located in the file **daily.ldb**.

Hex to ASCII decoding

It seems to be byte code, which creates characters that we still cannot read. I will use **ndisasm** to decode it into **Assembly**.

After researching online for a while, I understood the **function** of these **Assembly** snippets. Specifically:

These Assembly lines belong to the **Packer/Stub** (bootstrap code) of the malware. Its main purpose is to **self-decrypt** and unpack the malicious body into memory to evade detection by AV.
