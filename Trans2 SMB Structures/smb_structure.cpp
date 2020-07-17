//This code is from Snort

typedef struct smb_hdr
{
    uint8_t protocol[4];      /* Should always be 0xff,SMB */
    uint8_t command;          /* Command code */

    union
    {
        /* 32 Bits */
        struct {
            uint8_t errClass; /* Error class */
            uint8_t reserved; /* Should be 0 */
            uint16_t err;     /* Error code */
        } dosErr;
        uint32_t ntErrCode;    /* 32-bit Error code */
    } status;

    uint8_t flags;            /* Flags */
    uint16_t flags2;          /* 8 bits weren't enough */

    union
    {
        uint16_t pad[6];      /* Make this 12 bytes long */
        struct
        {
            uint16_t pidHigh; /* Upper 16 bits of PID */
            uint32_t unused;
            uint32_t unusedToo;
        } extra;
    } extended;

    uint16_t tid;             /* Tree ID */
    uint16_t pid;             /* Process ID */
    uint16_t uid;             /* User ID */
    uint16_t mid;             /* Multiplex ID */
} SMB_HDR;

typedef struct transaction2_hdr
{
    uint8_t wordCount;
    uint16_t totalParameterCount;
    uint16_t totalDataCount;
    uint16_t maxParameterCount;
    uint16_t maxDataCount;
    uint8_t maxSetupCount;
    uint8_t reserved;
    uint16_t flags;

    uint32_t timeout;
    uint16_t reserved2;

    uint16_t parameterCount;
    uint16_t parameterOffset;
    uint16_t dataCount;
    uint16_t dataOffset;

    uint8_t setupCount;
    uint8_t reserved3;

} SMB_TRANSACTION2_REQ;

typedef struct transaction2_secondary_hdr
{
    uint8_t wordCount;
    uint16_t totalParameterCount;
    uint16_t totalDataCount;

    uint16_t parameterCount;
    uint16_t parameterOffset;
    uint16_t parameterDisplacement;
    uint16_t dataCount;
    uint16_t dataOffset;
    uint16_t dataDisplacement;

    uint16_t fid;

    uint16_t byteCount;

} SMB_TRANSACTION2_SECONDARY_REQ;

/*
 * Grumble, grumble...
 *
 * Since IBM/Micrsoft decided to put SMBs out on the wire in
 * little endian order, the htonX & ntohX ops convert on the
 * wrong architectures -- ie, we need no conversion on little
 * endian.  So, use these for SMB...
 */

#ifdef WORDS_BIGENDIAN
#define smb_htons(A)  ((((u_int16_t)(A) & 0xff00) >> 8) | (((u_int16_t)(A) & 0x00ff) << 8))
#define smb_htonl(A)  ((((u_int32_t)(A) & 0xff000000) >> 24) | (((u_int32_t)(A) & 0x00ff0000) >> 8)  | (((u_int32_t)(A) & 0x0000ff00) << 8)  | (((u_int32_t)(A) & 0x000000ff) << 24))
#define smb_ntohs     smb_htons
#define smb_ntohl     smb_htonl
#define IS_LITTLE_ENDIAN 0
#else
#define smb_htons(A)  (A)
#define smb_htonl(A)  (A)
#define smb_ntohs(A)  (A)
#define smb_ntohl(A)  (A)
#define IS_LITTLE_ENDIAN 1
#endif

#define HAS_UNICODE_STRINGS(smbHdr) (smb_ntohs(smbHdr->flags2) & 0x8000)
