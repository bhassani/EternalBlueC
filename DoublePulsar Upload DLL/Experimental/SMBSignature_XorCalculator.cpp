/******************************************************************************

                            Online C Compiler.
                Code, Compile, Run and Debug C program online.
Write your code in this editor and press "Run" button to compile and execute it.

*******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

typedef uint64_t ULONGLONG;

typedef union _ULARGE_INTEGER {
  struct {
    uint32_t LowPart;
    uint32_t HighPart;
  } DUMMYSTRUCTNAME;
  struct {
    uint32_t LowPart;
    uint32_t HighPart;
  } u;
  ULONGLONG QuadPart;
} ULARGE_INTEGER;


#define byteswap16(value)		\
((WORD)((((value) >> 8) & 0xFF) | (((value) & 0xFF) << 8)))
#define byteswap32(value)		\
((((value) & 0xFF000000) >> 24) | (((value) & 0x00FF0000) >> 8) | (((value) & 0xFF00) << 8) | (((value) & 0xFF) << 24))
#define byteswap64(value)		\
((((value) & 0xFF00000000000000ULL) >> 56)		\
|	(((value) & 0x00FF000000000000ULL) >> 40)	\
|	(((value) & 0x0000FF0000000000ULL) >> 24)	\
|	(((value) & 0x000000FF00000000ULL) >> 8)	\
|	(((value) & 0x00000000FF000000ULL) << 8)	\
|	(((value) & 0x0000000000FF0000ULL) << 24)	\
|	(((value) & 0x000000000000FF00ULL) << 40)	\
|	(((value) & 0x00000000000000FFULL) << 56))


#define GetUlong(src)			\
*(DWORD *)(src)

#define GetUlonglong(src)		\
*(ULONGLONG*)(src)

#define PutUlonglong(dest, value)	\
*(ULONGLONG *)(dest) = (value)

unsigned long ComputeDOUBLEPULSARXorKey(unsigned long sig)
{
	unsigned long x = 2 * sig ^ ((((sig >> 16) | sig & 0xFF0000) >> 8) |
		(((sig << 16) | sig & 0xFF00) << 8));
	x = x & 0xffffffff;
	return x;
}


int main()
{
    ULONGLONG s = 0;
	ULARGE_INTEGER x = { 0 };
	
    //BYTE SecuritySignature[8];
    unsigned char resp[] = "\x79\xE7\xDF\x90\x00\x00\x00\x00";
    
    s = byteswap64(GetUlonglong(resp));
    s = GetUlonglong(resp);

    long signature = ComputeDOUBLEPULSARXorKey(s);
    printf("Your hex key is:  0x%llx\n", signature);
    printf("Your hex key should be:  0x58581162\n");
    return 0;
}
