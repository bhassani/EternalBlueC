UCHAR WordCount;  //Count of parameter words; value = (19 + SetupCount)
UCHAR MaxSetupCount; //count of setup words to return
USHORT Reserved;
ULONG TotalParameterCount; //Total count of parameter bytes being sent in the transaction request
ULONG TotalDataCount; //Total count of data bytes being sent in the transaction request

ULONG MaxParameterCount;       //Maximum count of parameter words to return.

ULONG MaxDataCount; 	//Maximum count of data words to return

ULONG ParameterCount; 	//Count of parameter bytes sent this buffer

ULONG ParameterOffset; 	//Offset (from header start) to Parameters

ULONG DataCount; 	//Count of data bytes sent this buffer. 

ULONG DataOffset; 	//Offset (from header start) to data

UCHAR SetupCount; 	//Count of setup words

USHORT Function; 	//The transaction function code

USHORT ByteCount; 	//Count of data bytes

UCHAR Parameters[12];
UCHAR Data[4096];
