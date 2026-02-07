---
layout: post
title: "XWorm RAT: Full Malware Analysis & Behavioral Breakdown"
date: 2026-02-05 12:00:00 +0200
categories: [Malware Analysis]
thumbnail: /assets/images/xworm-thumbnail.png
---

## XWorm RAT 
XWorm is a MaaS multifunctional RAT that was first discovered in 2022 with wide range of capabilities.<br>
*sample hash: `e4c179fa5bc03b07e64e65087afcbad04d40475204ebb0a0bc7d77f071222656`* <br>
*malware bazzar: `bazaar.abuse.ch/sample/e4c179fa5bc03b07e64e65087afcbad04d40475204ebb0a0bc7d77f071222656`* <br>
 
### static analysis
this PowerShell script was sort of interesting, if we looked closely we would find that these two hex values are PE files, because they start with **[4D 5A]**, which is the magic bytes for MZ hdr.

this is a common technique where one of them PEs is just a loader, and the other one is the actual payload.
![image](/assets/images/1.PNG)
how do we know the loader from the actual payload? if we looked closely we can conclude that `$YHYA` is the actual payload, that's because it was loaded to the memory (that simple!), that was later injected to RegSvcs.exe which's the loader.


![image](/assets/images/2.PNG)
and this a scheduler that runs this script every 2 mins.


![image](/assets/images/3.PNG)
simple obfuscation. i replaced the "!" signs and saved it as "xworm.file" so i can't accidentally run it analyzing the code. 


![image](/assets/images/4.png)
<p align="center">here's the scan for both, first one on the left is the ps script, the second is after extracting the payload.</p>
<br>

![image](/assets/images/5.PNG)
and it's a 32bit .NET binary.  i then looked at the binary imports -that were so suspicious-, strings, and intropy -which was kinda high-, and there were so much strings that were encrypted/decoded.
![image5](/assets/images/6.PNG)<br>


### code analysis
since it's a .NET binary, opened it in DnSpy and went to the EP. and that's what i first found:
![image](/assets/images/7.PNG)
there were some function that was frequently repeated, after parsing to it, it was so obvious that it was an AES encryption routine, with a 32 byte key length (128-bit).
![image](/assets/images/8.PNG)
after that i went to the arguments that were passed to the function,  likely there were the encrypted data that will be decrypted
![image](/assets/images/9.PNG)

i then managed to put a BP at the first line and passed over a couple of time and happened what was expected.
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
why is that? because it's going to use this copy later for persistence technique layers.

the first layer was Scheduled Task persistence task as expected
![image](/assets/images/13.PNG)
new ProcessStartInfo("schtasks.exe"); //opens schtasks.exe <br>
processStartInfo.WindowStyle = ProcessWindowStyle.Hidden; //hidden so the user don't notice.<br>
`/create  /f  /RL HIGHEST  /sc minute  /mo 1`  -> creates a task, overwrites if a one was there, run as highest privileges, and schedule: every minute.

here it's using Registry as a persistence technique at -> `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` , most common autostart location at windows.
![image](/assets/images/14.PNG)

this is another layer of persistence technique:
![image](/assets/images/15.PNG)
which's a Startup Folder persistence technique. 

![image](/assets/images/16.PNG)<br>
xworm is a multi-threaded malware, with separate threads handling persistence, C2/RAT logic, anti-debugging, and watchdog functionality.<br>
the behavioral analysis also reveals additional capabilities of this RAT.<br>

### behavioral analysis
after setting up my monitoring tools and opening the sample, and analyzing the  behavioral actions, i noticed tons of system changes, registry changes; tons of keys being read/deleted/changed/added,<br>
logs being deleted, files being added, and shockingly keystrokes being keylogged.<br>
here what i came up with..<br><br>


to keep persistency, as we saw at the code analysis section, xowrm copied itself a couple of times at `User\AppData\Roaming` and copying itself at startup
![image](/assets/images/writefilefilterd.PNG)
![image](/assets/images/ratinroaming folder.PNG)
![image](/assets/images/startup folder.PNG)<br><br>

i also found out that it was keylogging my keystrokes the whole time! and logging it at `User\AppData\Local\temp` as `log.tmp` 
![image](/assets/images/keylogger.PNG)
<br><br>

here it reads these what it called `desktop.ini`, this is a simple common technique for vm&sandbox detection.
![image](/assets/images/readinginis.PNG)
`C:\Users\desktop.ini`
`C:\Users\MaldevUser\Searches\desktop.ini` <br>
`C:\Users\MaldevUser\Contacts\desktop.ini` <br>
`C:\Users\MaldevUser\Favorites\desktop.ini` <br>
`C:\Users\MaldevUser\Links\desktop.ini` <br>
`C:\Users\MaldevUser\Saved Games\desktop.ini` <br>
`desktop.ini` is a standard, non-malicious Windows configuration file that stores customized folder settings like icons, localized names, and view options.<br>
the malware reads it so it can assume weather it's in a sandbox/vm or not, are folders are populated?, because as we know vms/sandboxes mostly do not contain much of folders.<br>
it's also kind of stealthy way of recon, allowing the malware to recon in a low noise <br><br>

there were so much reg keys created, on of theme is the one at `Run` as we saw earlier at the code analysis section
![image](/assets/images/run%20presistence.PNG)
to keep persistency .

after extracting ProcMon logs, with the help of ProcDot i managed to make this graph of sequence from the process creation and what did xowrm tried to do.
![image](/assets/images/procdotgraph sequence.png)
the malware reads several Windows registry keys related to internet zone settings to understand the network environment it is running in. 
these keys help determine:<br>
-whether the system is part of a local corporate network (Intranet) <br>
-whether network shares (UNC paths) are treated as trusted <br>
-whether internet traffic can bypass a proxy without inspection <br>

by checking these settings, the malware can decide if it is running on a personal machine
or a corporate environment, and adjust its behavior accordingly
(for example, choosing when or how to communicate with its command-and-control server).

### IOCs

| Category | Value | Notes |
|--------|-------|-------|
| Domain  | mo1010.duckdns.org | possible C2 server
| Network | TCP Port: 7000 | default listening port |
| File |  RegSvcs.exe | malware loader | 
| File | xworm.exe | main malware binary |
| File | xworm.lnk | startup persistence |
| File | log.tmp | keystrokes logs |
| Registry | HKCU\Software\Microsoft\Windows\CurrentVersion\Run | auto-start |
| Registry | HKCU\...\ZoneMap\ProxyBypass | proxy detection |


