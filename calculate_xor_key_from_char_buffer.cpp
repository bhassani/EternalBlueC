/*

Source used: https://shasaurabh.blogspot.com/2017/05/doublepulsar-backdoor.html

takes a sample char from an SMB response.
Converts the signature to an unsigned int and swaps it so that it can then be used to generate
the doublepulsar key to encrypt the payload

Program receives SMB signature as: \x79\xe7\xdf\x90
signature is converted to unsigned int and reversed to: 0x90dfe779
Run this value in the doublepulsar XOR key calculator: 0x58581162

*/

#include <stdio.h>
#include <stdint.h>

unsigned int LE2INT(unsigned char *data)
{
            unsigned int b;
            b = data[3];
            b <<= 8;
            b += data[2];
            b <<= 8;
            b += data[1];
            b <<= 8;
            b += data[0];
            return b;
}
        
unsigned int ComputeDOUBLEPULSARXorKey(unsigned int sig)
{
	uint32_t x = (2 * sig ^ (((sig & 0xff00 | (sig << 16)) << 8) | (((sig >> 16) | sig & 0xff0000) >> 8))) & 0xffffffff;
	x = x & 0xffffffff;
	
	return x;
}

int main()
{
    unsigned char signature[] = "\x79\xe7\xdf\x90";
    unsigned int reverse = LE2INT(signature);
    printf("our signatured flipped & converted into an unsigned integer:  0x%x\n",reverse);
    unsigned int new_key = ComputeDOUBLEPULSARXorKey(reverse);
    printf("our computed doublepulsar XOR key:  0x%x\n",new_key);
    return 0;
}
