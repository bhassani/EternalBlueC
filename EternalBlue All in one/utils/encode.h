#ifndef ENCODE_H_INCLUDED
#define ENCODE_H_INCLUDED

char *decrypt_xor(char *pBuf, int bufSize, char ch);
void rc4_crypt(unsigned char *_s,unsigned char *Data, unsigned long data_len);
char *b2a_hex(unsigned char *bindata, char *strdata, int binlength);
void rc4_init(unsigned char *s,unsigned char *key, unsigned long key_len);
char * base64_encode( const unsigned char * bindata, char * base64, int binlength );
int base64_decode( const char * base64, unsigned char * bindata );

#endif // ENCODE_H_INCLUDED
