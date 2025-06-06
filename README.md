[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## EternalBlueC
EternalBlue suite remade in C/C++ which includes:
- MS17-010 Exploit ( Contains DoublePulsar )
- EternalBlue/MS17-010 vulnerability detector
- DoublePulsar detector
- DoublePulsar Upload DLL ( Hex editing  )
- Doublepulsar Upload Shellcode ( Hex editing )
- Doublepulsar Upload Exe inside a DLL ( Wannacry style )
- DoublePulsar Upload DLL with SMB Structure 
- Doublepulsar Upload Shellcode with SMB Structure 

## Project accomplishments
- Upload Shellcode - completed and working, inject your shellcode into any process you desire
- Upload DLL       - completed, functionality works but DLL runs only in the context of LSASS
- Upload DLL with an embedded exe ( Wannacry method ) - completed, functionality works but DLL runs only in the context of LSASS and drops the executable as "mssecsvc.exe"

## Project goals

- Implement an interface application to interact with Doublepulsar such as Uploading shellcode or a DLL without crashing the target. 

- Implement a scanner & attack GUI in C#, C++, Java & Python3

- Allow editing of EternalBlue exploit payload to remove DoublePulsar and allow custom payloads & shellcode to be sent instead.

- Add EternalRomance (requires Named Pipe) support

## Clarifications
The EternalBlue / MS17-010 Exploit that will be included in this project installs DoublePulsar only<br />
As of now, it doesn't contain any other payloads besides installing the DoublePulsar implant, hopefully that will change when I have extra time.

## EternalBlue Suite

* **ms17_vuln_status.cpp** - This program sends 4 SMB packets.  1 negotiation, 1 session setup, 1 tree connect and 1 TransNamedPipe request.  This program then reads the NT_STATUS response from the TransNamedPipeRequest ( PeekNamedPipe request ) and determines if NT_STATUS in the SMB packet = 0xC0000205 ( STATUS_INSUFF_SERVER_RESOURCES ).  If this is correct, then the target is vulnerable to MS17-010.  Tested on unpatched Windows 7 x64 bit.

![ms17vulnstatus](/images/ms17vulnstatus.PNG)

* **doublepulsar_check.cpp** - This program sends 4 SMB packets.  1 negotiation, 1 session setup, 1 tree connect and Trans2 SESSION_SETUP packet.  By sending the Trans2 SESSION_SETUP packet, the multiplex id sent ( 41 ) can be compared in the Trans2 response packet against multiplex ID: 0x51 or 81.  If that is the response, that means DoublePulsar is present on the machine.  DoublePulsar reads the sent multiplex ID and after the ping command is successful, returns a +10 in hexadecimal for the multiplex ID in the Trans2 SESSION_SETUP response.  Afterwards, commands are sent (which are sent in the timeout parameters of the SMB packet) to burn the DoublePulsar backdoor.  DoublePulsar becomes dormant and not removed.  Tested on Windows 7 x64 bit.

![doublepulsar_check](/images/doublepulsar_check.PNG)

* **DoublePulsarXORKeyCalculator.cpp** - This program sends 4 SMB packets.  1 negotiation packet and 3 requests.  The last request is a Trans2 SESSION_SETUP request.  A Trans2 SESSION_SETUP response is then received and the SMB signature is extracted at (Recvbuff[18] -> Recvbuff[22]) .  Recvbuff[22] indicates the architecture type.  If 1, the target is x64 bits and if 0, the target is x86/32 bits.  The SMB signature is converted from the hex characters into an unsigned integer.  

![SMBSignatureWireshark](/images/SMB_Signature_Wireshark.PNG)

These values from Recvbuff[18] -> Recvbuff[22] are then ran through the DoublePulsar XOR key calculator function, which generates a XOR key (unsigned integer) that can be used to encrypt the shellcode or DLL payload that will be uploaded to DoublePulsar.  Tested on Windows 7 x64 bit.

Sample screenshot:

![XORCalculator](/images/XORKeyCalculator.PNG)

Same key from the original NSA binary in FUZZBUNCH
![XORCalculatorFromNSAbinary](/images/DoublepulsarKeyOriginal.png)

* **DoublePulsar_structure_ping.cpp** - This program sends 4 SMB packets.  1 negotiation, 1 session setup, 1 tree connect and Trans2 SESSION_SETUP packet.  The difference between this and doublepulsar_check.cpp is that this generates the Trans2 DoublePulsar PING packet using a structure rather than hardcoded that I stole from Wannacry.  Another difference is that this program dynamically generates the TreeConnect packet rather than hardcoded.  The ping packet generated from this will tell you if DoublePulsar is present on the remote machine.

* **DoublePulsar_structure_exec.cpp** - This program sends 6 SMB packets.  1 negotiation, 1 session setup, 1 tree connect, 1 Doublepulsar Trans2 SESSION_SETUP Ping packet and 1 Doublepulsar Trans2 SESSION_SETUP Execution packet.

* **Doublepulsar_UploadDLL.cpp** - 
This program is intended for DLLs.  This program sends 4 SMB packets.  1 negotiation, 1 session setup, 1 tree connect, 1 Ping Trans2 SESSION_SETUP request and an Execution Trans2 SESSION_SETUP packet.  The Ping Trans2 SESSION_SETUP request packet is sent to obtain the SMB signature in the Trans2 SESSION_SETUP response packet. This signature is processed through the DoublePulsar XOR key calculator. The program then reads a DLL file (Example: payload.dll) and combines it with 64 bit kernel and userland shellcode to run the DLL ( Stolen from Wannacry ) and XORs the buffer with the DoublePulsar XOR key we calculated from the SMB signature.  A packet is generated by allocating memory, copying the Trans2 packet, editing the values needed for the SMB transaction to work ( UserID, TreeID, TotalDataCount, DataCount, ByteCount ) then copying the XORed data (kernel shellcode (userland shellcode included) + DLL) to the end and loop through it sending it at a total packet length of 4096 bytes at a time to DoublePulsar.  Total packet length = 4178.  4096 is for the XOR encrypted data.  Will also implement using SMB & TRANSACTION2 structure.

* **Doublepulsar_UploadShellcode.cpp** - This program sends 5 SMB packets.  1 negotiation, 1 session setup, 1 tree connect, 1 Ping Trans2 SESSION_SETUP packet and 1 execute Trans2 SESSION_SETUP packet.  The Trans2 SESSION SETUP request packet is sent to obtain the SMB signature in the TRANS2 SESSION_SETUP response packet. This signature is processed through the DoublePulsar XOR key calculator.  The program then copies kernel shellcode and sample shellcode from a buffer, it XORs the buffer with the DoublePulsar XOR key we calculated from the SMB signature.  A packet is generated by allocating memory, copying the Trans2 exec packet (from Wannacry), edits the values needed for the SMB transaction to work ( UserID, TreeID, TotalDataCount, DataCount, ByteCount ) then copying the SESSION_SETUP Parameters and 4096 bytes of XORed shellcode data (the encrypted shellcode) to the end and send it at a total packet length of 4178 bytes to DoublePulsar.  Total packet length = 4178.  NetBIOS length will be 4174 since the NetBIOS header does NOT count itself for the size.  12 bytes of this packet is for the Doublepulsar SESSION_PARAMETERS.  4096 is for the XORed encrypted data.  Will also implement using SMB & TRANSACTION2 structure.

Shellcode generated from:
https://www.rapid7.com/blog/post/2019/10/02/open-source-command-and-control-of-the-doublepulsar-implant/ <br />
zerosum0x0 wrote custom shellcode for ETERNALBLUE that could be repurposed for DOUBLEPULSAR, albeit with a small modification. Since the syscall overwrite in the copied shellcode was unnecessary for this use case, we undefined it: <br />
;%define SYSCALL_OVERWRITE             ; to run at process IRQL in syscall <br />
recompile with: nasm -w-other -o >(xxd -p -c 16 | sed 's/../\\x&/g') external/source/shellcode/windows/multi_arch_kernel_queue_apc.asm <br />
https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/multi_arch_kernel_queue_apc.asm <br />
https://raw.githubusercontent.com/ninp0/eternalblue/master/eternalblue_kshellcode_x64.asm <br />
https://raw.githubusercontent.com/ninp0/eternalblue/master/eternalblue_kshellcode_x86.asm <br />

![UploadShellcode](/images/DOPU-UploadShellcode.jpg)

* **DoublePulsar_UploadExe.cpp** - 
This program is intended for EXECUTABLES.  The executable will be read into memory and placed in a Wannacry launcher DLL and sent via DoublePulsar.  1 negotiation, 1 session setup, 1 tree connect, 1 Ping Trans2 SESSION_SETUP packet and 1 exec Trans2 SESSION_SETUP packet.  The Trans2 SESSION SETUP request packet is sent to obtain the SMB signature in the Trans2 SESSION_SETUP response packet. This signature is processed through the DoublePulsar XOR key calculator. Then the program reads an EXE file (Example: putty.exe) and combines it with 64 bit kernel and userland shellcode & a skeleton DLL file ( Stolen from Wannacry ) and XORs the buffer with the DoublePulsar XOR key we calculated from the SMB signature.  A packet is generated by allocating memory, copying the Trans2 packet, editing the values needed for the SMB transaction to work ( UserID, TreeID, TotalDataCount, DataCount, ByteCount) then copying the XORed data (kernel shellcode + DLL + Executable) to the end and loop through it sending it at a total packet length of 4096 bytes at a time to DoublePulsar.  Total packet length = 4178.  NetBIOS length will be 4174 since the NetBIOS header does NOT count itself for the size.  12 bytes of this packet is for the Doublepulsar SESSION_PARAMETERS.  4096 is for the XORed encrypted data.

* **EternalBlue.cpp** - This program sends multiple SMB packets.  Negotiation, SessionSetup, TreeConnect and multiple NT trans and Trans2 packets.  These NT trans packets are malformed which grooms the exploit in memory on the victim computer.  More whitespace or empty SMB packets are sent to the victim over multiple sockets to the same port on the victim.  Most of EternalBlue's base64 payload is being sent over socket 1 where the Negotiation, SessionSetup & TreeConnect packets were sent on.  Then 20 other sockets are created and data is being sent to those sockets ( Socket 3 to Socket 21 ).  Afterwards DoublePulsar is sent on Socket 3 to Socket 21.  The sockets are then closed by the program which detonates EternalBlue & DoublePulsar on the victim computer.  A SMB disconnect and SMB logoff request is then sent and the connection closes.  This exploit works and was tested on Windows 7 x64 bit.  It took around 5 seconds for the backdoor to fully be operational, as already reported with EternalBlue writeups around the internet.  More exploitation attempts may be necessary.  However there currently is a bug with the TreeID & UserID not being correctly set in the packets, which will be fixed in a later release.  This will work against machines that are recently turned on as the TreeID and UserIDs are set to the default values.  These packets will have to have their TreeID and UserID values updated as they are currently set to default values "08 00".
![EternalBlue](/images/eternalbluecpp.PNG)
![EternalBlue_cmd](/images/eternalbluecmd.PNG)
![eternalbluepackets](/images/eternalbluepackets.PNG)

## Metasploit module

- 2021 Update: Now includes experimental Metasploit module!
- 2021 Update: Now includes experimental Wannacry DLL wrapper for Metasploit payload! ( Still in development )
- 2021 Update: Now includes experimental Wannacry DLL wrapper for C++ ( Still in development )

Metasploit module that I made functional using the open source DoublePulsar RCE module from Metasploit.

I changed the logic to allow a DLL to be generated, merge it with the x64 kernel shellcode (prepended) that I stole from Wannacry, to allow DoublePulsar to run the DLL.

![msfconsole](/images/msfconsole.PNG)

Part 2:
I changed the logic to allow an executable metasploit payload to be generated, merge it with the x64 kernel shellcode (prepended) that I stole from Wannacry, and stole the Wannacry launcher DLL to allow DoublePulsar to run the launcher DLL.

## Extra education code

Repository also contains the following for educational purposes and are NOT supported by me:

- DoublePulsar x86/x64 Upload DLL python script

- EternalBlue All in one binary

- Multi arch kernel queue apc assembly code & Windows x86/x64 Multi-Arch Kernel Ring 0 to Ring 3 via Queued APC kernel code

- EternalBlue x64/x86 kernel payload shellcode from worawit

- Eternalblue replay file

