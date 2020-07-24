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
  uint8_t	WordCount                 //15
  uint16_t TotalParameterCount       //12
  uint16_t TotalDataCount            //4096
  uint16_t MaxParameterCount         //1
  uint16_t MaxDataCount              //0
  uint8_t MaxSetupCount             //0
  uint8_t Reserved1                  //00
  uint16_t Flags                     //0x0000
  uint32_t Timeout                   //25 89 1a 00
  uint16_t Reserved2                  //0000
  uint16_t ParameterCount            //12
  uint16_t ParameterOffset           //66
  uint16_t DataCount                 //4096
  uint16_t DataOffset                //78
  uint8_t SetupCount                //1
  uint8_t Reserved3                  //0
  uint16_t Subcommand                //0x000e
  uint16_t ByteCount                 //4109
  Padding                   //00
  Parameters[12]            //SESSION_SETUP Parameters
  Data[4096]                //SESSION_SETUP Data

} WANNACRY_PCAP_TYPES;
