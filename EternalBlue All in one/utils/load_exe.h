#ifndef LOAD_EXE_H_INCLUDED
#define LOAD_EXE_H_INCLUDED

#include <windows.h>

int fork_process(unsigned char *lpImage, char *pCmdLine, char *pDummyPath,
                 STARTUPINFO *pStartInfo, PROCESS_INFORMATION *pProcInfo,
                 int *pPid, HANDLE *phProc);

#endif // LOAD_EXE_H_INCLUDED
