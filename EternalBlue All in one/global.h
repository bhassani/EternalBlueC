#ifndef GLOBAL_H_INCLUDED
#define GLOBAL_H_INCLUDED

typedef struct _Enc_Res_Desc_
{
    char *pBufAddr;        //malloc
    int bufSize;
    int status;
}ENC_RES_DESC;

typedef struct _Target_Desc_
{
    char ip[20];
    char port[10];
    char proto[10];
    char osVer[100];
    char osArch[100];
    char osSp[100];
    char pipeName[100];
    char expName[100];
    long touchTime;
}TARGET_DESC;

#endif // GLOBAL_H_INCLUDED
