---
layout: post
title: "Hancitor: Multi-Stage Infection Chain Analysis & Reverse Engineering"
date: 2026-10-14 12:00:00 +0200
categories: [Malware Analysis]
---


## Hancitor 
Hancitor(aka Chanitor) emerged in 2013 which spread via social engineering techniques mainly through phishing mails embedded with malicious link and weaponized Microsoft office document contains malicious macro in it.<br>


### Delivery Analysis
A typical Word document lure requesting the user to run the VBA macro. Also, I noticed here that there was an object embedded in the doc file; I opened its properties, and it was a DLL file.
![image](/assets/images/hancitor/1.PNG)

Using oletools, some malicious functionalities were flagged, alongside these two DLLs which happened to come across one of them. We will see later that it was being used somehow to deliver the second stage.<br>
![image](/assets/images/hancitor/2.PNG)
The macro uses the Document_Open() subroutine, which runs automatically as soon as the document is opened. This eliminates the need for any user interaction beyond opening the file (And ofcourse enabling the macros).

As shown here, the document contains two macros. Additionally, at section 19, an embedded object was identified.
![image](/assets/images/hancitor/3.PNG)
I proceeded to extract all of these components, the embedded object and the two macros; for further investigation.

The macro avoids writing the suspicious command rundll32 in plain text. Instead, it splits the string into two parts:
`bbb = "rund"``cvzz = "l3" & "2"` (which evaluates to "l32")
When concatenated, they form "rundll32". This technique is used to evade static detection by antivirus solutions and security tools.
![image](/assets/images/hancitor/6.PNG)
The macro declares a function named gc that aliases the Windows API ShellExecuteA from shell32.dll. This function is used to execute arbitrary files or commands. The alias gc is intentionally misleading to hide its true purpose.

The macro performs the following steps:
1. Searches the user's Word template directory for `kikus.dll`.
2. If not found, it calls yyy() to copy data from the document itself (likely a hidden object or text).
3. Calls hdhdd() to recursively search the temp folder for `kiks.dll`.
4. If found, renames `kiks.dll` to `kikus.dll` in the template directory.

Once `kikus.dll` is in place, the macro executes:
`rundll32 "C:\Users\...\Templates\kikus.dll,GBSLWSDVGOE"`,
This cmd runs the exported function `GBSLWSDVGOE` from the malicious DLL.


As for the dumped object, I went ahead and opened it in HxD, and we can see here from the MZ that it's a PE file, except there was some garbage.
![image](/assets/images/hancitor/4.PNG)

And it is a DLL and appears to be packed. In the following section, we will proceed with unpacking it and extracting the next stage.![image](/assets/images/hancitor/5.PNG)

### Second-Stage Payload Extraction
I went ahead and passed it to x32dbg, opened the DLL with rundll32.exe, with `GBSLWSDVGOE` being the chosen exported function![image](/assets/images/hancitor/7.PNG)

After that, i put some breakpoints on these memory-related apis
![image](/assets/images/hancitor/8.PNG)

The dumped payload appears to be compressed with `aPLib`, evidenced by the presence of the M8Z magic bytes, which is the `aPLib` decompression signature.
![image](/assets/images/hancitor/9.PNG)

At first, I wrote a simple Python script to try and decompress the payload, and it worked pretty well. However, after comming a cross some analyses, I found out that if you scroll down the dumped file a bit, you would find the decompressed one, no coding needed :D. Now all you have to do is just clean it, and now we're ready for the code analysis..
![image](/assets/images/hancitor/10.PNG)

I have covered the unpacking and decompression section in a YouTube video [in Arabic]. Feel free to watch it for a detailed walkthrough: [Watch the video on YouTube](https://youtu.be/i4ITA1zWbhA?si=nF2NmBSMm6MWgYqQ)

### Code Analysis
Usually I start my analysis by going through the imports and the strings (if they are not obfuscated), but this will definitely help us in a moment. But since there were only two exported functions, I went ahead and checked them.
![image](/assets/images/hancitor/11.PNG)
#### C2 Communication & Beaconing
As I was going through the functions, I noticed that it was fetching some system and user information, and there was this `GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)` format string. Obviously, that was some sort of URL construction: `GUID` = unique machine identifier, `INFO` = the info that was fetched, `IP` = the IP address returned by ipify and etc...


![image](/assets/images/hancitor/12.PNG)
![image](/assets/images/hancitor/13.PNG)

The malware here decrypts strings and then passes them to wsprintfA, so the final output would look something like this: `GUID=12345678901234567&BUILD=19044&INFO=DESKTOP-ABC\MalDevUser&EXT=CORP;corp.example.com;&IP=197.45.123.67&TYPE=1&WIN=10.0(x32)`.

Now the next logical step is to reach the C2 server and try to exfiltrate the data. and that's waht `mw_internet_stuff` going to do.This function is responsible for C2 communication. It sends an HTTP POST request to the C2 server, with the victim's information embedded in the URL. The server's response is then stored in the lpBuffer variable for further processing.
![image](/assets/images/hancitor/15.PNG)
_mw_internet_stuff inside beaconing_
![image](/assets/images/hancitor/14.PNG)
After a successful beaconing request, the malware processes the C2 response through this command retrieval and execution loop.
First, the response buffer is passed to `mw_xor_decryption`, which decrypts the data and stores the result in a secondary buffer. The malware then enters a loop that processes and checks each command individually.
![image](/assets/images/hancitor/16.PNG)
The `mw_xor_decryption` function is a simple `XOR` string decryption routine used by the malware to try and hide its strings.

Now let's dive in and see what `mw_cmds_checking_and_executing` actually does.
![image](/assets/images/hancitor/17.PNG)
The `mw_cmds_checking_and_executing` function acts as the command dispatcher for the malware. It receives format string from the C2 server and routes it to the right handler based on the first character of the command. i figuered that the cmd commes in such `X:arguments` format, then every fuction here does its work.. let's check the first one.


**case 'b'** **mw_download_and_decompress_and_pinject**
![image](/assets/images/hancitor/18.PNG)
The b command triggers the malware's process injection routine.first allocates a 5 MB buffer and downloads and decompresses the payload from the provided URL. The payload then was passed, then performs the actual Process Hollowing and Injection stuff.

The injection process follows these steps:
PE Validation: `mw_is_PE_file` checks that the payload is actually a PE or not, using `MZ` signature.
![image](/assets/images/hancitor/21.PNG)
Process Creation:` mw_create_svchost_suspended` creates a new `svchost.exe` process in a suspended state.
![image](/assets/images/hancitor/20.PNG)
Code Injection: `mw_process_injection` injects the payload into `svchost.exe`.
![image](/assets/images/hancitor/22.PNG)
Context Manipulation & Execution: `mw_process_hollowing` modifies the thread context and resumes it, to try and make the injected code to run.
![image](/assets/images/hancitor/23.PNG)
PID Retrieval: If successful, `GetProcessId` returns the PID of the new process, if it was not, `TerminateProcess` it will be called.


**case 'e' mw_download_pe_map_execute** <br>
This case was responsible  for `mw_download_pe_map_execute`: downloading a PE file, allocate it a memory, resolve and build its improt table, then, executing it 
![image](/assets/images/hancitor/24.PNG)
![image](/assets/images/hancitor/25.PNG)
After the payload has been mapped into memory, the malware will resolve the Import Address Table `(IAT)` before it can executea, and since the payload was loaded via Manual Mapping rather than `LoadLibrary`, the Windows loader did not resolve its imports automatically. then the malware has to do this task manually.

This is handled by `mw_dynamic_api_resolving`, which does these following steps:
1. Locate the Export Directory: The function walks the PE's export directory using `IMAGE_DIRECTORY_ENTRY_EXPORT` pointer in the optional header `(a1 + 60 + 128)`.
2.Iterate Over Imported Modules: For each module in the import table (e.g., kernel32.dll, user32.dll), it attempts to try and gets a handle using `GetModuleHandleA`. If the module is not already loaded, it'll go ahead and calls `LoadLibraryA`.
3. Iterate Over Imported Functions: For each function it'll calls `GetProcAddress` to get the function's address.
4. Patch the IAT: The resolved address is written into the right IAT slot, replacing the original import stub.
This is repeated for every imported module and function until the entire IAT is resolved. then, the payload's imports are fully functional, now he can call whatever windows api as if it was loaded manually.

But why all of this? These sort of Manual Mapping bypasses the Windows loader entirely, which means the payload never appears in the process's module list, and is not registered with the system. However, this also means the loader cannot resolve imports, so the malware has to go and do it manually. This technique is commonly used by advanced malware and packers to evade detection by security tools that rely on the Windows loader's behavior.


**case 'l' mw_download_shellcode_execute** <br>
For this one, it was responsible for downloading and executing a shellcode 
![image](/assets/images/hancitor/26.PNG)
![image](/assets/images/hancitor/28.PNG)
![image](/assets/images/hancitor/29.PNG)


`mw_sc_process_injection` performs Shellcode Injection. Unlike PE Injection, the payload here is raw Shellcode, it does not require PE parsing or any Manual Mapping, or API resolving. The Shellcode is written and executed directly into memory via `CreateRemoteThread` (remotely) by injecting the Shellcode in `svchost` or `CreateThread` (locally).


**case 'r' mw_write_to_disk_execute** <br>
This case here is different from toher cases, since here it actually goes and writes to doisk..
![image](/assets/images/hancitor/27.PNG)
it saves the downloaded binary to `%TEMP%` under a randomized name with the `BN` prefix. If the file was an EXE it'll go ahead and lunches a nother child process, and it will be executed via `rundll32.exe` if it was a DLL.


### Config Decryption & Extraction
Previously when i was parsing through the functions, i could not help but notice these Windows Crypto functions, you can get here either by frisking the imports, or parsing the the exported fuction
![image](/assets/images/hancitor/31.PNG)
Here, it's checking if anything was written to the buffer where the data will be decrypted. Then it goes and copies the encrypted data to the buffer, and then goes ahead and performs the decryption on the buffer.

![image](/assets/images/hancitor/32.PNG)
![image](/assets/images/hancitor/30.PNG)
Here The malware uses the Windows Crypto APIs to try and decrypt its config. The decryption sequence consists of five chained API calls:

`CryptAcquireContextA`: Acquires a handle to a cryptographic service provider (CSP). The flag `0xF0000000` `(CRYPT_VERIFYCONTEXT)` indicates that no persistent key container is needed.

1. `CryptCreateHash`: Creates an empty hash object using the SHA-1 algorithm (CALG_SHA).

2. `CryptHashData`: Hashes the encryption key (pbData, 8 bytes) into the hash object.

3. `CryptDeriveKey`: Derives a session key from the hash using the `RC4` algorithm `(CALG_RC4)`. The flags `0x280011 ``(CRYPT_EXPORTABLE | CRYPT_NO_SALT | ...)` control how the key is generated.

4. `CryptDecrypt`: Decrypts the data in place (a1) using the derived RC4 key. The Final flag is set to true, indicating this is the final block.

Using all of that, we can do it the lazy way simply by going ahead and using CyberChef for the decryption.
So, earlier we saw how it retrieves the key, computes the `CALG_SHA` (SHA-1) hash of it, and then only uses `0x28` bits of the key. Since `0x28/8 = 5` bytes, So I went ahead and calculated the SHA-1 hash of it.
![image](/assets/images/hancitor/33.PNG)

Went back, copied all the encrypted data region, pasted it, used the first 5 bytes of the hashed key, and there we go, it was all plaintext.
![image](/assets/images/hancitor/34.PNG)


### IOCs
`http://thestacultur.com/8/forum.php` <br>
`http://arguendinfuld.ru/8/forum.php` <br>
`http://waxotheousch.ru/8/forum.php`  <br>
User-agent: "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko"

*document   hash: `ea34b79b2ee2bab3ff01e738a9886d967d2b1d4e8b65e84b99495dab447b97e8`* <br>
*dumped obj hash: `d710e304520b1a7f27206cc5427e6401a8f2ed3093221ca3f2594b482db57b68`* <br>
*1st stage  hash: `9b61df3d60d98aa5bf8ad335a4e1175c0b2481d18849cf87ee73ac05c7c1838e`* <br>
*2nd stage  hash: `990a4cd6dd9575cbd2122f560ff68420c1c9dbfde3c9d6a5181b0f54a7e497cd`* <br>

kikus.dll <br>
kiks.dll <br>


MITRE: <br>
User Execution – T1204  <br>
Web Protocols – T1071.001 <br>
Dynamic-link Library Injection – T1055.001 <br>
Remote System Discovery – T1018 <br>
Network Service Scanning – T1046 <br>
Windows Service – T1543.003 <br>
Domain Trust Discovery – T1482 <br>
System Time Discovery – T1124 <br>
Network Share Discovery – T1135 <br>
File Deletion – T1070.004 <br>
Internal case 4301 <br>

