//Contains a SMB Trans2 Request, SESSION_SETUP from a Wannacry PCAP

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
  uint8	WordCount                 //15
  uint16 TotalParameterCount       //12
  uint16 TotalDataCount            //4096
  uint16 MaxParameterCount         //1
  uint16 MaxDataCount              //0
  uint8 MaxSetupCount             //0
  uint8 Reserved1                  //00
  uint16 Flags                     //0x0000
  uint32 Timeout                   //25 89 1a 00
  uint16 Reserved2                  //0000
  uint16 ParameterCount            //12
  uint16 ParameterOffset           //66
  uint16 DataCount                 //4096
  uint16 DataOffset                //78
  uint8 SetupCount                //1
  uint8 Reserved3                  //0
  uint16 Subcommand                //0x000e
  uint16 ByteCount                 //4109
  Padding                   //00
  Parameters[12]            //SESSION_SETUP Parameters
  Data[4096]                //SESSION_SETUP Data

} WANNACRY_PCAP_TYPES;
