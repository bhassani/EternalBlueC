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
