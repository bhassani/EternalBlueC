typedef struct _SMB_HEADER
{
	UCHAR    Protocol[4];
	UCHAR    Command;
	NTSTATUS Status;
	UCHAR    Flags;
	USHORT   Flags2;
	USHORT   PIDHigh;
	UCHAR    SecurityFeatures[8];
	USHORT   Reserved;
	USHORT   TID;
	USHORT   PIDLow;
	USHORT   UID;
	USHORT   MID;
} SMB_HEADER, * PSMB_HEADER;

//
// Header for reading oncoming requests
// from client.
//
typedef struct _SMB_TRANS2_PARAM_HEADER
{
	UCHAR  WordCount;
	struct Words
	{
		USHORT TotalParameterCount;
		USHORT TotalDataCount;
		USHORT Reserved1;
		USHORT ParameterCount;
		USHORT ParameterOffset;
		USHORT ParameterDisplacement;
		USHORT DataCount;
		USHORT DataOffset;
		USHORT DataDisplacement;
		UCHAR  SetupCount;
		UCHAR  Reserved2;
		USHORT Setup[1];
	};
} SMB_TRANS2_HDR, * PSMB_TRANS2_HDR;

//from somewhere else

typedef struct {
	uint16 SmbMessageType; //0x00
	uint16 SmbMessageLength; 
	uint8 ProtocolHeader[4]; //"\xffSMB"
	uint8 SmbCommand; 
	uint32 NtStatus; //0x00000000
	uint8 flags; //0x18 - pathnames not case sensitive & pathnames canonicalized
	uint16 flags2;  //0xC001 (Unicode & Nt error types & longfilename support
	uint16 ProcessIDHigh; //0x00
	uint8 signature[8]; //0x00000000000
	uint16 reserved; //0x0000
	uint16 TreeId; 
	uint16 ProccessID; //0xfeff
	uint16 UserID; 
	uint16 multipleID;  //Incremental 64bytes en cada request.
	//char buffer[16384]; // Custom SmbCommand data
} smheader;

typedef struct {
	uint8 WordCount;
	uint16 TotalParameterCount;
	uint16 TotalDataCount;
	uint16 MaxParameterCount;
	uint16 MaxDataCount;
	uint8 MaxSetupCount;
	uint8 reserved;
	uint16 flags;
	uint32 timeout;
	uint16 reserved2;
	uint16 ParameterCount;
	uint16 ParameterOffset;
	uint16 DataCount;
	uint16 DataOffset;
	uint8 SetupCount; 
	uint8 reserved3;
	uint16 Function; 
	//uint16 FID;
	uint16 ByteCount; 
	uint8 padding;
	uint8 TransactionName[14];
	//uint16 padding2;
  char buffer[4096];
} SMB_COM_TRANS2;


SMB_COM_TRANS2 packet;
memcpy(&packet, recvbuff, sizeof(packet),0);
