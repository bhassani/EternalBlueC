unsigned char 64_bit_kernel_shellcode[] = "64 bit kernel shellcode here that is referenced";

//Update Shellcode to include the DLL size
//0x591 = 1425
&64_bit_kernel_shellcode[1425] = 0x7D70; //32112

//Update Shellcode to include the DLL ordinal
&64_bit_kernel_shellcode[FIND_VALUE] = 1;

//Value is possibly: 1429 or 0x595


