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
