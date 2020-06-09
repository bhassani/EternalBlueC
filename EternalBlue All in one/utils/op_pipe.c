#include "op_pipe.h"

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

enum _create_anonymous_pipe_ret_
{
    CRE_ANONY_P_NORMAL = 0,
    CRE_ANONY_P_ERR_STDIN,
    CRE_ANONY_P_ERR_STDOUT
};
ANONY_PIPE_DESC create_anony_pipe_with_io()
{
    //创建可以与标准I/O绑定的匿名管道
    ANONY_PIPE_DESC pipeDesc;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    memset(&pipeDesc, 0x00, sizeof(pipeDesc));
    memset(&sa, NULL, sizeof(SECURITY_ATTRIBUTES));
    memset(&sa, NULL, sizeof(SECURITY_ATTRIBUTES));
    memset(&pi, NULL, sizeof(PROCESS_INFORMATION));

    //创建两个匿名管道
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = 0;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&pipeDesc.hRdStdin, &pipeDesc.hWrStdin, &sa, 0))
    {
        pipeDesc.status = CRE_ANONY_P_ERR_STDIN;
        return pipeDesc;
    }
    if (!CreatePipe(&pipeDesc.hRdStdout, &pipeDesc.hWrStdout, &sa, 0))
    {
        pipeDesc.status = CRE_ANONY_P_ERR_STDOUT;
        return pipeDesc;
    }

    //管道与I/O绑定
    GetStartupInfo(&pipeDesc.si);
    pipeDesc.si.cb = sizeof(STARTUPINFO);
    pipeDesc.si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    pipeDesc.si.wShowWindow = SW_HIDE;
    pipeDesc.si.hStdInput = pipeDesc.hRdStdin;
    pipeDesc.si.hStdOutput = si.hStdError = pipeDesc.hWrStdout;

    pipeDesc.status = CRE_ANONY_P_NORMAL;

    return pipeDesc;
}

int terminal_process(HANDLE hProc)
{
    int retVal;

    retVal = TerminateProcess(hProc, 0);
    if(retVal == 0)
    {
        retVal = GetLastError();
    }

    return retVal;
}

int close_anony_pipe(ANONY_PIPE_DESC *pPipeDesc)
{
    CloseHandle(pPipeDesc->hRdStdin);
    CloseHandle(pPipeDesc->hRdStdout);
    CloseHandle(pPipeDesc->hWrStdin);
    CloseHandle(pPipeDesc->hWrStdout);
    CloseHandle(pPipeDesc->pi.hProcess);
    CloseHandle(pPipeDesc->pi.hThread);

    memset(pPipeDesc, 0x00, sizeof(ANONY_PIPE_DESC));
    pPipeDesc->status = -1;

    return 0;
}

enum _recv_from_anony_pipe_ret_
{
    RCV_PIPE_NORMAL = 0,
    RCV_PIPE_ERR_PARAM,
    RCV_PIPE_ERR_RECV,
    RCV_PIPE_ERR_PEEK,
};
int recv_from_anony_pipe(ANONY_PIPE_DESC *pPipeDesc,
                         int(*recv_handler)(char *, int, void *),
                         void *hdrParam,
                         int(*need_exit)(void *),
                         void *exParam,
                         int block)
{
    /*
    阻塞函数，从标准输出流中读取数据
    pPipeDesc: 管道描述字
    recv_handler: 接收后的回调处理函数，返回值 0: 不退出 1: 退出
    hdrParam: 接收回调函数传入参数
    need_exit: 监视是否在阻塞情况下有退出请求，返回值 0: 不退出 1: 退出
    exParam: 判断退出函数的参数
    block: 1：阻塞函数 0：不阻塞
    */
    char recvBuf[PIPE_RECV_BUFF_SIZE];
    int lBytesRead = 0;
    int lastErr = 0;
    int exitCode = 0;

    if(pPipeDesc->status < 0)
    {
        return RCV_PIPE_ERR_PARAM;
    }

    while (1)
    {
        //检查子进程是否退出
        GetExitCodeProcess(pPipeDesc->pi.hProcess, &exitCode);

        do
        {
            memset(recvBuf, 0x00, sizeof(recvBuf));
            if(PeekNamedPipe(pPipeDesc->hRdStdout, recvBuf, sizeof(recvBuf) - 1, &lBytesRead, 0, 0) != 0)
            {
                if(lBytesRead > 0)
                {
                    //recv from pipe
                    if (!ReadFile(pPipeDesc->hRdStdout, recvBuf, sizeof(recvBuf) - 1, &lBytesRead, 0))
                    {
                        return RCV_PIPE_ERR_RECV;
                    }

                    if(recv_handler != NULL)
                    {
                        if(recv_handler(recvBuf, lBytesRead, hdrParam) != 0)
                        {
                            return RCV_PIPE_NORMAL;
                        }
                    }
                    else
                    {
                        printf("%s", recvBuf);
                    }
                }
            }
            else
            {
                lastErr = GetLastError();
                return RCV_PIPE_ERR_PEEK;
            }
        }
        while(lBytesRead > 0);

        if(need_exit != NULL)
        {
            if(need_exit(exParam) != 0)
            {
                return RCV_PIPE_NORMAL;
            }
        }
        if(block == 0)
        {
            return RCV_PIPE_NORMAL;
        }

        //子进程已退出
        if(exitCode != STILL_ACTIVE)
        {
            return RCV_PIPE_NORMAL;
        }

        Sleep(100);
    }

    return RCV_PIPE_NORMAL;
}

typedef struct __Full_Recv_Param_
{
    char *pRecvBuf;
    int bufSize;

} _FULL_RCV_PARAM;

typedef struct __Exit_Param_
{
    unsigned long startTime;
    unsigned long timeout;
} _EXIT_PARAM;

static int _need_exit(void *param)
{
    _EXIT_PARAM *pParam = (_EXIT_PARAM *)param;
    unsigned long currTime = time(NULL);

    if(pParam->timeout <= 0)
        return 0;

    if(currTime - pParam->startTime > pParam->timeout)
        return 1;

    return 0;
}

static int _recv_handler(char *pBuf, int bufSize, void *param)
{
    _FULL_RCV_PARAM *pParam = (_FULL_RCV_PARAM *)param;

    if(pParam->pRecvBuf == NULL)
    {
        pParam->pRecvBuf = (char *)malloc(bufSize + 1);
        if(pParam->pRecvBuf == NULL)
            return -1;
        memset(pParam->pRecvBuf, 0x00, bufSize + 1);
    }
    else
    {
        pParam->pRecvBuf = (char *)realloc(pParam->pRecvBuf,
                                           pParam->bufSize + bufSize + 1);
        if(pParam->pRecvBuf == NULL)
            return -1;
        memset(pParam->pRecvBuf + pParam->bufSize, 0x00, bufSize + 1);
    }

    memcpy(pParam->pRecvBuf + pParam->bufSize, pBuf, bufSize);
    pParam->bufSize += bufSize;

    return 0;
}

enum _full_recv_from_anony_pipe_ret_
{
    FULL_RCV_NORMAL = 0,
    FULL_RCV_ERR_RECV,
};
int full_recv_from_anony_pipe(ANONY_PIPE_DESC *pPipeDesc, char **ppBuf,
                              int *bufSize, unsigned long timeout)
{
    _FULL_RCV_PARAM fullRcvParam;
    _EXIT_PARAM exitParam;
    unsigned long startTime = 0;
    int recvRetVal = 0;

    memset(&fullRcvParam, 0x00, sizeof(fullRcvParam));
    memset(&exitParam, 0x00, sizeof(exitParam));

    exitParam.startTime = time(NULL);
    exitParam.timeout = timeout;

    while(1)
    {
        recvRetVal = recv_from_anony_pipe(pPipeDesc,
                                          _recv_handler,
                                          (void *)&fullRcvParam,
                                          _need_exit,
                                          (void *)&exitParam,
                                          1);
        *ppBuf = fullRcvParam.pRecvBuf;
        *bufSize = fullRcvParam.bufSize;

        if(recvRetVal != RCV_PIPE_NORMAL)
        {
            printf("[-] Recv from anonymous pipe failed. ErrCode: %d\n", recvRetVal);
            return FULL_RCV_ERR_RECV;
        }
        else
        {
            break;
        }
    }

    return FULL_RCV_NORMAL;
}







