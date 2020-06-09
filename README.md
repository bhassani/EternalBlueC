# EternalBlueC
Scanner for a machine's MS17-010 vulnerability status &amp; DoublePulsar backdoor detector

ms17_vuln_status.cpp - This program sends 4 SMB packets and reads the NT_STATUS response from a TransNamedPipeRequest ( PeekNamedPipe request ) and determines if NT_STATUS = 0xC0000205 ( STATUS_INSUFF_SERVER_RESOURCES ).  If this is the correct response, then the target is vulnerable to MS17-010.  Tested on unpatched Windows 7 x64 bit.

doublepulsar_check.cpp - This program sends 4 SMB requests and sends a Trans2 session setup request.  Doing so, the multiplex id can be compared against value: 0x51 or 81.  If that is the response, that means DoublePulsar is present on the machine.  Afterwards, you can send commands to burn the DoublePulsar backdoor.  ( NOTE: DoublePulsar becomes dormant and not removed ).  Tested on Windows 7 x64 bit.

Repository also contains
  * DoublePulsar Upload DLL python scripts & DoublePulsar x64 userland shellcode for DLL injection
  * EternalBlue All in one binary
  * Multi arch kernel queue apc assembly code & Windows x86/x64 Multi-Arch Kernel Ring 0 to Ring 3 via Queued APC kernel code
  * EternalBlue x64/x86 kernel shellcode from worowit
  * Eternalblue replay file
