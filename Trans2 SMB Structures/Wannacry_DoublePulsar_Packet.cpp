//Contains a SMB Trans2 Request, SESSION_SETUP from a Wannacry PCAP

/*
https://www.microsoft.com/security/blog/2017/06/30/exploring-the-crypt-analysis-of-the-wannacrypt-ransomware-smb-exploit-propagation/

The picture above shows that the SESSION_SETUP parameter fields are used to indicate the offset and total lengths of payload bytes.

The data is 12 bytes long—the first four bytes indicate total length
the next four bytes is reserved, and the last 4 bytes are the current offsets of the payload bytes in little-endian. 
These fields are encoded with master XOR key

Because the reserved field is supposed to be 0, the reserved field is actually the same as the master XOR key. 
Going back to the packet capture above, the reserved field value is 0x38a9dbb6, which is the master XOR key. 
The total length is encoded as 0x38f9b8be. When this length is XORed with the master XOR key, it is 0x506308
which is the actual length of the payload bytes being uploaded. 
The last field is 0x38b09bb6. When XORed with the master key, this last field becomes 0, 
meaning this packet is the first packet of the payload upload.


The transferred and decoded bytes are of size 0x50730c. 
As a whole, these packet bytes include kernel shellcode, userland shellcode, and the main WannaCrypt PE packages.

*/

/*

https://shasaurabh.blogspot.com/2017/05/doublepulsar-backdoor.html

Trans2.SESSION_SETUP.Parameters is of 0xC (12) bytes and contains below information encrypted by XOR key.
1. Total Size of Payload
2. Chunk Size
3. Offset of Chunk in Payload

Trans2.SESSION_SETUP.Parameters value = 6a620858 62015858 62115858
Total Size of Payload = (0x5808626a) ^ (0x58581162) = 0x507308
 Chunk Size = (0x58580162) ^ (0x58581162) = 0x1000(4096)
Offset of Chunk in Payload = (0x58581162) ^ (0x58581162) = 0

Another example of Trans2.SESSION_SETUP.Parameters value = 6a620858 62015858 62015858
Total Size of Payload = (0x5808626a) ^ (0x58581162) = 0x507308
Chunk Size = (0x58580162) ^ (0x58580162) = 0x1000(4096)
Offset of Chunk in Payload = (0x58580162) ^ (0x58581162) = 0x1000(4096)

*/

//SMB Trans2 Request: 0x32
typedef struct {
  WordCount                 //15
  TotalParameterCount       //12
  TotalDataCount            //4096
  MaxParameterCount         //1
  MaxDataCount              //0
  MaxSetupCount             //0
  Reserved                  //00
  Flags                     //0x0000
  Timeout                   //25 89 1a 00
  Reserved                  //0000
  ParameterCount            //12
  ParameterOffset           //66
  DataCount                 //4096
  DataOffset                //78
  SetupCount                //1
  Reserved                  //0
  Subcommand                //0x000e
  ByteCount                 //4109
  Padding                   //00
  Parameters[12]            //SESSION_SETUP Parameters
  Data[4096]                //SESSION_SETUP Data

} WANNACRY_PCAP;

//tried to add the types.  Should be accurate!
typedef struct {
  uint8_t	WordCount;                 //15
  uint16_t TotalParameterCount;       //12
  uint16_t TotalDataCount;            //4096
  uint16_t MaxParameterCount;         //1
  uint16_t MaxDataCount;              //0
  uint8_t MaxSetupCount ;            //0
  uint8_t Reserved1;                  //00
  uint16_t Flags;                     //0x0000
  uint32_t Timeout;                   //25 89 1a 00
  uint16_t Reserved2;                  //0000
  uint16_t ParameterCount;            //12
  uint16_t ParameterOffset;           //66
  uint16_t DataCount;                 //4096
  uint16_t DataOffset;                //78
  uint8_t SetupCount;                //1
  uint8_t Reserved3;                  //0
  uint16_t Subcommand;                //0x000e
  uint16_t ByteCount;                 //4109
  uint8_t Padding                   //00
  Parameters[12]            //SESSION_SETUP Parameters
  Data[4096]                //SESSION_SETUP Data

} WANNACRY_PCAP_TYPES;

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
00 00 00		//No idea what this is



Hex value | Decimal value
104e = 4174
0d10 = 3344



//Wannacry PING packet extracted from Wannacry
00 00 00 		//NetBIOS header
00 4E 			//SMB Len
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
41 00			//Multiple ID

0F			//WordCount
0C 00 			//TotalParamCount
00 00			//TotalDataCount
01 00			//Max Param Count
00 00			//Max Data Count
00			//Max Setup Count
00			//Reserved
00 00			//Flags
01 34 EE 00		//Timeout -> Execute command
00 00 			//Reserved
0C 00 			//Parameter Count
42 00			//Parameter Offset
00 00			//Data Count ( same as: TotalDataCount )
4E 00			//Data Offset
01			//Setup Count
00 			//Reserved
0E 00			//Subcommand: SESSION_SETUP
0D 00			//ByteCount
00 00 00 00 00 00 00 00 00 00 00 00 //SESSION_SETUP Parameters
