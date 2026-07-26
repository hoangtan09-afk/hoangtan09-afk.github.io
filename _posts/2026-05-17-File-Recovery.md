---
title: "File Recovery"
date: 2026-05-17 00:00:00 +07000
categories: [Forensics]

---

**Introduce: This is a hands-on lab that simulates a real-world forensic case in which analysts recover deleted files and evidence using FTK Imager and Autopsy. Let me step into the role of a digital forensics expert.**

===============================================================================================

<br>
I created a disk partition (Z:) with only 250MB so the lab environment would be easier to manage. In real life, analysts would examine the full contents of important drives such as C or D.

![pic1](/assets/img/posts/FileRecovery/pic1.png)

Inside the Z: drive, I created two files. These files serve as stand-ins for important pieces of evidence.

![pic2](/assets/img/posts/FileRecovery/pic2.png)

The contents of the files are shown in the two images below.

![pic3](/assets/img/posts/FileRecovery/pic3.png)

![pic4](/assets/img/posts/FileRecovery/pic4.png)

Now imagine that a hacker gained access to this machine and deleted these two important files. Suppose I am the attacker, and I delete them in two different ways.

I will delete the first file simply by pressing Delete, which sends it to the Recycle Bin.

![pic5](/assets/img/posts/FileRecovery/pic5.png)

I will permanently delete the second file by pressing Shift + Delete.

![pic6](/assets/img/posts/FileRecovery/pic6.png)

At this point, the drive appears empty.

![pic7](/assets/img/posts/FileRecovery/pic7.png)

This is where we step in as digital forensics analysts. We must do whatever is necessary to recover the deleted files to support the investigation.

For forensic analysts, we do not investigate the target machine directly. Instead, we create a forensic image of the drive, copy it to a removable device such as an external hard drive or USB, and bring it to the lab for analysis.

We will follow the same procedure. First, create a copy of the Z: drive with **FTK Imager**.

![pic8](/assets/img/posts/FileRecovery/pic8.png)

Select Logical Drive.

![pic9](/assets/img/posts/FileRecovery/pic9.png)

Select the drive to copy.

![pic10](/assets/img/posts/FileRecovery/pic10.png)

Choose the .dd format.

![pic11](/assets/img/posts/FileRecovery/pic11.png)

For the case file name, any name is acceptable. Then click Next.

![pic12](/assets/img/posts/FileRecovery/pic12.png)

Choose the output directory and name the image file.

![pic13](/assets/img/posts/FileRecovery/pic13.png)

Then click Start.

![pic14](/assets/img/posts/FileRecovery/pic14.png)

Once completed, we get the hash values shown in the image. In my view, this is important information to preserve because hashes are used to verify the integrity of the evidence. You should save them somewhere easy to find.

![pic15](/assets/img/posts/FileRecovery/pic15.png)

The copied image of the drive will look like this if you follow the steps successfully. This file cannot be opened normally.

We will use **Autopsy** to open it, a forensic tool used to investigate disk images and evidence.

![pic16](/assets/img/posts/FileRecovery/pic16.png)

Select New Case and then name it.

![pic17](/assets/img/posts/FileRecovery/pic17.png)

Here, point to the image file of the original drive, then click Next.

The main interface of **Autopsy**:

![pic18](/assets/img/posts/FileRecovery/pic18.png)

There are many interesting sections here that I want to introduce, such as clicking **Timeline**.

![pic19](/assets/img/posts/FileRecovery/pic19.png)

This records the timeline of events that changed the contents of the drive.

When you switch to the List tab, you will see the full chronological logs of events such as file creation, access, modification, and deletion. Of course, this includes the files we created and deleted at the beginning of the lab.

![pic20](/assets/img/posts/FileRecovery/pic20.png)

The file SECRET was created at 22:16, and SUPER SECRET at 22:17:

![pic21](/assets/img/posts/FileRecovery/pic21.png)

The files were accessed at 22:18:

![pic22](/assets/img/posts/FileRecovery/pic22.png)

The same pattern applies to other events such as **modified** and **file changed**, which are recorded in a very complete way. So any action taken on the disk is logged and closely monitored. **Autopsy** helps us inspect these logs clearly and intuitively.

<br>
<br>

I will point out the difference between the two deletion methods from the beginning of the lab. The following image helps illustrate it:

![pic23](/assets/img/posts/FileRecovery/pic23.png)

File SECRET was initially deleted in a way that moved it to the Recycle Bin, so we still see it appear below, reported as being inside **/$RECYCLE.BIN/**.

![pic24](/assets/img/posts/FileRecovery/pic24.png)

The content matches exactly what we wrote into the file earlier.

<br>

Unlike SECRET, SUPER SECRET was deleted permanently, so after the Modified event for SUPER SECRET, we no longer see it.

![pic25](/assets/img/posts/FileRecovery/pic25.png)

**So how do we recover these two files?**

Return to the main Autopsy interface and look under Deleted Files.

![pic27](/assets/img/posts/FileRecovery/pic27.png)

Open file system.

![pic28](/assets/img/posts/FileRecovery/pic28.png)

**These are the evidence items we need to recover.**

![pic29](/assets/img/posts/FileRecovery/pic29.png)
![pic30](/assets/img/posts/FileRecovery/pic30.png)

The content matches exactly what we originally created.

To recover the files properly, right-click and choose extract files.

![pic31](/assets/img/posts/FileRecovery/pic31.png)
![pic32](/assets/img/posts/FileRecovery/pic32.png)

I will restore them to their original location.

![pic33](/assets/img/posts/FileRecovery/pic33.png)
![pic34](/assets/img/posts/FileRecovery/pic34.png)

As a result, we have successfully recovered the deleted files and completed the work of a forensic analyst (the same process applies to the remaining file).

<br>

If you have followed this all the way through, I hope this lab will spark your interest and curiosity. I would love to share more techniques from the world of forensics with you. Thank you for taking the time to read and follow along, and I wish you a great day!




