---
layout: post
title: "XWorm RAT: Full Malware Analysis & Behavioral Breakdown"
date: 2026-02-05 12:00:00 +0200
categories: [Malware Analysis]
image: /assets/images/xworm-thumbnail.png
---

## XWorm RAT 
XWorm is a MaaS multifunctional RAT that was first discovered in 2022 with wide range of capabilities.<br>
<span style="color: white;">*malware bazzarsample: e4c179fa5bc03b07e64e65087afcbad04d40475204ebb0a0bc7d77f071222656*
 </span>

### static analysis
this PowerShell script was sortf of interresting, if we looked closely we would find that these two hex values are PE files, becaise they start with **[4D 5A]**, which is the magic bytes for MZ hdr.

this is a common technique where one of them PEs is just a loader, and the other one is the acutal payload.
![image](/assets/images/1.PNG)
how do we know the loader from the actual payload? if we looked closely we can conclode that $YHYA is the acutal one, that's because it was loaded to the memory (that simple!), that was later injected to RegSvcs.exe which's the loader.


![image](/assets/images/2.PNG)
and this a scheduler that runs this script every 2 mins.


![image](/assets/images/3.PNG)
simple obufscation. i replaced the "!" signs and saved it as "xworm.file" so i can't accidentally run before i analyze the code. 


![image](/assets/images/4.png)
<p align="center">here's the scan for both, first one on the left is the ps script, the second is after extracting the payload.</p>
<br>

![image](/assets/images/5.PNG)
and it's a 32bit .NET binary.  i then looked at the binary imports -that were so suspicious-, strings, and intropy -which was kinda high-, and there were so much strings that were encrypted/decoded.
![image5](/assets/images/6.PNG)<br>


### code analysis
since it's a .NET binary, opend it in DnSpy and went to the EP. and that's what i firist found:
![image](/assets/images/7.PNG)
since it's a .NET binary, opend it in DnSpy and went to the EP. and that's what i firist found:
![image](/assets/images/8.PNG)
after that i went to the arguments that were passed to the function, and it was likely the encrypted data that will be decrypted:
![image](/assets/images/9.PNG)

i then managed to put a BP at the first line and passed over a couple of time and happed what was expected.
![image](/assets/images/10.PNG)

i made a watch window and passed the encrypted function arguments to speed up the process and that's what i found:
![image](/assets/images/11.PNG)
the first value was a domain -> `"mo1010.duckdns.org"` which's most likely the C2 server.<br>
the second one `"7000"` -> the port.<br>
the other ones i couldn't tell exactly what were they,
except for `"C:\User\MaldevUser\AppData\Roaming"`, i thought that it was the path were it was going to be an instance of the malware, because when i first run it, i found it copies itself at the same path.

This code confirms what i was saying above, here it makes an instance of itself at the path:
![image](/assets/images/12.PNG)
if the file exists, it overwrites it, then sleeps for 1000 seconds. <br>
why is that? because it's going to use this copy later for presistence technique layers.

the first layer was Scheduled Task persistence task as expected
![image](/assets/images/13.PNG)
new ProcessStartInfo("schtasks.exe"); //opens schtasks.exe <br>
processStartInfo.WindowStyle = ProcessWindowStyle.Hidden; //hidden so the user don't notice.<br>
`/create  /f  /RL HIGHEST  /sc minute  /mo 1`  -> creats a task, overwrites if a one was there, run as highest privileges, and schedule: every minute.

here it's using Registery as a persistence technique at -> `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` , most common autostart location at windows.
![image](/assets/images/14.PNG)

this is another layer of persistence technique:
![image](/assets/images/15.PNG)
which's a Startup Folder persistence technique. 

![image](/assets/images/16.PNG)<br>
xworm is a multi-threaded malware, with separate threads handling persistence, C2/RAT logic, anti-debugging, and watchdog functionality.<br>
the behavioral analysis also reveals additional capabilities of this RAT.<br>

### behavioral analysis
after setting up my monitoring tools,

