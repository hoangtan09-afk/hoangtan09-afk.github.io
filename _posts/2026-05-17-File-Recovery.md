---
title: "File Recovery Lab"
date: 2026-05-17 00:00:00 +07000
categories: [Forensics]

---

**Introduction**

This hands-on lab simulates a real-world **digital forensics scenario**, demonstrating the recovery of **deleted files and evidence** using industry-standard tools: **FTK Imager** and **Autopsy**. In this exercise, we will assume the role of a **digital forensics expert** to investigate a **compromised system**.

---

### Phase 1: Environment Setup and Incident Simulation

To create a manageable lab environment, a dedicated **250MB disk partition (Z:)** was provisioned. In a real-world investigation, analysts typically examine **full-capacity drives** (e.g., C: or D:).

![pic1](/assets/img/posts/FileRecovery/pic1.png)

Within the Z: drive, two files were created to represent **critical evidentiary data**.

![pic2](/assets/img/posts/FileRecovery/pic2.png)

The contents of these files are detailed in the images below:

![pic3](/assets/img/posts/FileRecovery/pic3.png)

![pic4](/assets/img/posts/FileRecovery/pic4.png)

**Simulating the Attack:** 
Suppose a **malicious actor** gains unauthorized access to this system and attempts to **destroy the evidence**. We will simulate this by deleting the two files using different methods:

1. **Standard Deletion:** The first file is deleted using the standard `Delete` key, which moves it to the **Recycle Bin**.

![pic5](/assets/img/posts/FileRecovery/pic5.png)

2. **Permanent Deletion:** The second file is permanently deleted using `Shift + Delete`, bypassing the Recycle Bin entirely.

![pic6](/assets/img/posts/FileRecovery/pic6.png)

Following these actions, the drive appears **completely empty** to a standard user.

![pic7](/assets/img/posts/FileRecovery/pic7.png)

### Phase 2: Evidence Acquisition

As **digital forensics analysts**, our objective is to **recover these deleted files** to support an investigation. 

A fundamental rule of digital forensics is to **never investigate the target machine directly**. Instead, we acquire a **forensic image** of the drive, transfer it to a **secure storage medium**, and analyze it in an **isolated laboratory environment**.

We will proceed by creating a forensic copy of the Z: drive using **FTK Imager**.

![pic8](/assets/img/posts/FileRecovery/pic8.png)

Select **Logical Drive** as the source type.

![pic9](/assets/img/posts/FileRecovery/pic9.png)

Choose the **target drive (Z:)** for acquisition.

![pic10](/assets/img/posts/FileRecovery/pic10.png)

Select the **Raw (dd)** image format for a **bit-by-bit copy**.

![pic11](/assets/img/posts/FileRecovery/pic11.png)

Provide an appropriate case or file name (any identifier is acceptable for this lab), then proceed by clicking **Next**.

![pic12](/assets/img/posts/FileRecovery/pic12.png)

Specify the **destination directory** and assign a name to the **output image file**.

![pic13](/assets/img/posts/FileRecovery/pic13.png)

Click **Start** to begin the imaging process.

![pic14](/assets/img/posts/FileRecovery/pic14.png)

Upon completion, FTK Imager generates **verification hashes (MD5, SHA-1)**. **Preserving these hash values is critical**, as they guarantee the **integrity of the evidence** throughout the investigation. Ensure these are documented securely.

![pic15](/assets/img/posts/FileRecovery/pic15.png)

The resulting **forensic image file** cannot be mounted or opened by a standard operating system. It requires **specialized forensic software** for analysis.

### Phase 3: Forensic Analysis with Autopsy

We will utilize **Autopsy**, a powerful **digital forensics platform**, to analyze the acquired disk image and extract the necessary evidence.

![pic16](/assets/img/posts/FileRecovery/pic16.png)

Begin by selecting **New Case** and assigning it a descriptive name.

![pic17](/assets/img/posts/FileRecovery/pic17.png)

Add a **new data source**, pointing to the forensic image file created in the previous step, and click **Next**.

**Navigating Autopsy:**
The main interface of Autopsy provides **comprehensive tools** for examining the evidence.

![pic18](/assets/img/posts/FileRecovery/pic18.png)

A particularly valuable feature for investigations is the **Timeline** analysis.

![pic19](/assets/img/posts/FileRecovery/pic19.png)

This section reconstructs the **chronological sequence of events** on the drive.

By switching to the **List** tab, analysts can review **detailed logs of file system activity**, including file creation, access, modification, and deletion. As expected, the actions performed at the beginning of this lab are accurately recorded.

![pic20](/assets/img/posts/FileRecovery/pic20.png)

* The file `SECRET` was created at 22:16, followed by `SUPER SECRET` at 22:17.

![pic21](/assets/img/posts/FileRecovery/pic21.png)

* Both files were subsequently accessed at 22:18.

![pic22](/assets/img/posts/FileRecovery/pic22.png)

Similar chronological patterns apply to other file system events (e.g., modified, changed). Autopsy effectively translates complex disk activity into an **intuitive, readable format**, ensuring that any action taken on the system is **logged and traceable**.

#### Analyzing Deletion Methods

The **Timeline feature** clearly illustrates the distinction between the two deletion methods executed earlier.

![pic23](/assets/img/posts/FileRecovery/pic23.png)

The file `SECRET` was subjected to a **standard deletion**. Consequently, traces of it remain visible, with its location reported under the **/$RECYCLE.BIN/** directory.

![pic24](/assets/img/posts/FileRecovery/pic24.png)

Extracting this file reveals that its contents **remain intact** and match the original data.

Conversely, `SUPER SECRET` underwent **permanent deletion** (`Shift + Delete`). After its final "Modified" event, the file system **no longer actively tracks it**.

![pic25](/assets/img/posts/FileRecovery/pic25.png)

### Phase 4: File Recovery and Extraction

To recover these files, navigate back to the primary Autopsy interface and locate the **Deleted Files** section in the directory tree.

![pic27](/assets/img/posts/FileRecovery/pic27.png)

Expand the **File System** node.

![pic28](/assets/img/posts/FileRecovery/pic28.png)

Here, we locate the **remnants of our deleted evidence**. 

![pic29](/assets/img/posts/FileRecovery/pic29.png)
![pic30](/assets/img/posts/FileRecovery/pic30.png)

By examining the data, we can confirm the contents match our original files perfectly.

To formally recover the evidence, right-click the target file and select **Extract File(s)**.

![pic31](/assets/img/posts/FileRecovery/pic31.png)
![pic32](/assets/img/posts/FileRecovery/pic32.png)

In this scenario, we will extract the recovered files back to an **analysis directory**.

![pic33](/assets/img/posts/FileRecovery/pic33.png)
![pic34](/assets/img/posts/FileRecovery/pic34.png)

### Conclusion

Through this process, we have successfully acquired a **forensic image**, analyzed **file system activity**, and **recovered deleted evidence**, effectively mirroring the workflow of a **digital forensics analyst**. This identical procedure can be applied to recover the remaining file.

If you have followed along, I hope this lab has provided valuable insight into the fascinating field of **digital forensics**. Thank you for your time, and I look forward to sharing more advanced techniques in the future!
