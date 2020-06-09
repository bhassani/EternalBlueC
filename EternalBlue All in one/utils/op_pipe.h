#ifndef OP_PIPE_H_INCLUDED
#define OP_PIPE_H_INCLUDED

#include <windows.h>

#define PIPE_RECV_BUFF_SIZE 1024

typedef struct _Anonymous_Pipe_Desc_
{
    int status;
    HANDLE hProc;
    HANDLE hRdStdin;
    HANDLE hWrStdin;
    HANDLE hRdStdout;
    HANDLE hWrStdout;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
}ANONY_PIPE_DESC;

ANONY_PIPE_DESC create_anony_pipe_with_io();
int terminal_process(HANDLE hProc);
int close_anony_pipe(ANONY_PIPE_DESC *pPipeDesc);
int recv_from_anony_pipe(ANONY_PIPE_DESC *pPipeDesc,
                         int(*recv_handler)(char *, int, void *),
                         void *hdrParam,
                         int(*need_exit)(void *),
                         void *exParam,
                         int block);
int full_recv_from_anony_pipe(ANONY_PIPE_DESC *pPipeDesc, char **ppBuf,
                              int *bufSize, unsigned long timeout);

#endif // OP_PIPE_H_INCLUDED
