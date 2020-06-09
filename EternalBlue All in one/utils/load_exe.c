#include "load_exe.h"

#include <stdio.h>
#include <windows.h>

typedef long int (__stdcall* NtUnmapViewOfSectionF)(HANDLE, PVOID);

enum _fork_proc_ret_
{
    FORK_PROC_SUCCESS = 0,
    FORK_PROC_ERR_MALLOC,
    FORK_PROC_ERR_GET_DUMMY,
    FORK_PROC_ERR_OPEN_DUMMY,
    FORK_PROC_ERR_DOS_HDR,
    FORK_PROC_ERR_NT_HDR,
    FORK_PROC_ERR_FORK_DOS_HDR,
    FORK_PROC_ERR_FORK_NT_HDR,
    FORK_PROC_ERR_WR_MEM_IMG,
    FORK_PROC_ERR_WR_MEM_CTX,
    FORK_PROC_ERR_CRE_PROC,
};
int fork_process(unsigned char *lpImage, char *pCmdLine, char *pDummyPath,
                 STARTUPINFO *pStartInfo, PROCESS_INFORMATION *pProcInfo,
                 int *pPid, HANDLE *phProc)
{
    /*
    lpImage: 内存中EXE地址
    pCmdLine: 启动的命令行
    pDummyPath: 指定一个傀儡进程
    pStartInfo: 设置可以绑定I/O句柄
    pProcInfo: 进程启动参数
    pPid: 返回子进程pid
    */
    long int                lWritten;
    long int                lHeaderSize;
    long int                lImageSize;
    long int                lSectionCount;
    long int                lSectionSize;
    long int                lFirstSection;
    long int                lPreviousProtection;
    long int                lJumpSize;
    LPVOID                  lpImageMemory;
    LPVOID                  lpImageMemoryDummy;
    IMAGE_DOS_HEADER        dsDosHeader;
    IMAGE_NT_HEADERS        ntNtHeader;
    IMAGE_SECTION_HEADER    shSections[512 * 2];
    PROCESS_INFORMATION     piProcessInformation;
    STARTUPINFO             suStartUpInformation;
    CONTEXT                 cContext;
    char                    *pCmdLineBuf;
    int                     cmdBufLen;

    // Variables for Local Process
    FILE*                   fFile;
    char*                   pProcessName;
    long int                lFileSize;
    long int                lLocalImageBase;
    long int                lLocalImageSize;
    LPVOID                  lpLocalFile;
    IMAGE_DOS_HEADER        dsLocalDosHeader;
    IMAGE_NT_HEADERS        ntLocalNtHeader;

    NtUnmapViewOfSectionF NtUnmapViewOfSection =
        (NtUnmapViewOfSectionF)GetProcAddress(LoadLibrary("ntdll.dll"),
                "NtUnmapViewOfSection");

    // End Variable Definition
    pProcessName = (char *)malloc(MAX_PATH);
    if(pProcessName == NULL)
    {
        return FORK_PROC_ERR_MALLOC;
    }
    memset(pProcessName, 0x00, MAX_PATH);

    if(pDummyPath == NULL)
    {
        // 使用自身当作傀儡进程
        if(GetModuleFileName(NULL, pProcessName, MAX_PATH) == 0)
        {
            free(pProcessName);
            return FORK_PROC_ERR_GET_DUMMY;
        }
    }
    else
    {
        strcat(pProcessName, pDummyPath);
    }

    // Open the dummy process in binary mode
    fFile = fopen(pProcessName, "rb");
    if(fFile == NULL)
    {
        free(pProcessName);
        return FORK_PROC_ERR_OPEN_DUMMY;
    }
    fseek(fFile, 0, SEEK_END);

    // Get file size
    lFileSize = ftell(fFile);
    rewind(fFile);

    // Allocate memory for dummy file
    lpLocalFile = (LPVOID)malloc(lFileSize);
    if(lpLocalFile == NULL)
    {
        free(pProcessName);
        return FORK_PROC_ERR_MALLOC;
    }
    memset(lpLocalFile, 0x00, lFileSize);

    // Read memory of file
    fread(lpLocalFile, lFileSize, 1, fFile);

    // Close file
    fclose(fFile);

    // Grab the DOS Headers
    memcpy(&dsLocalDosHeader, lpLocalFile, sizeof(dsLocalDosHeader));
    if(dsLocalDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        free(pProcessName);
        free(lpLocalFile);
        return FORK_PROC_ERR_DOS_HDR;
    }

    // Grab NT Headers
    memcpy(&ntLocalNtHeader,
           (LPVOID)((long int)lpLocalFile + dsLocalDosHeader.e_lfanew),
           sizeof(  dsLocalDosHeader));
    if(ntLocalNtHeader.Signature != IMAGE_NT_SIGNATURE)
    {
        free(pProcessName);
        free(lpLocalFile);
        return FORK_PROC_ERR_NT_HDR;
    }

    // Get Size and Image Base
    lLocalImageBase = ntLocalNtHeader.OptionalHeader.ImageBase;
    lLocalImageSize = ntLocalNtHeader.OptionalHeader.SizeOfImage;

    // Deallocate
    free(lpLocalFile);

    // Grab DOS Header for Forking Process
    memcpy(&dsDosHeader, lpImage, sizeof(dsDosHeader));
    if(dsDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        free(pProcessName);
        return FORK_PROC_ERR_FORK_DOS_HDR;
    }

    // Grab NT Header for Forking Process
    memcpy(&ntNtHeader, (LPVOID)((long int)lpImage + dsDosHeader.e_lfanew), sizeof(ntNtHeader));
    if(ntNtHeader.Signature != IMAGE_NT_SIGNATURE)
    {
        free(pProcessName);
        return FORK_PROC_ERR_FORK_NT_HDR;
    }

    // Get proper sizes
    lImageSize = ntNtHeader.OptionalHeader.SizeOfImage;
    lHeaderSize = ntNtHeader.OptionalHeader.SizeOfHeaders;

    // Allocate memory for image
    lpImageMemory = (LPVOID)malloc(lImageSize);
    if(lpImageMemory == NULL)
    {
        free(pProcessName);
        return FORK_PROC_ERR_MALLOC;
    }
    memset(lpImageMemory, 0x00, lImageSize);
    lpImageMemoryDummy = lpImageMemory;
    lFirstSection = (long int)(((long int)lpImage + dsDosHeader.e_lfanew) + sizeof(IMAGE_NT_HEADERS));
    memcpy(shSections, (LPVOID)(lFirstSection),
           sizeof(IMAGE_SECTION_HEADER) * ntNtHeader.FileHeader.NumberOfSections);
    memcpy(lpImageMemoryDummy, lpImage, lHeaderSize);

    // Get Section Alignment
    if((ntNtHeader.OptionalHeader.SizeOfHeaders % ntNtHeader.OptionalHeader.SectionAlignment) == 0)
    {
        lJumpSize = ntNtHeader.OptionalHeader.SizeOfHeaders;
    }
    else
    {
        lJumpSize = (ntNtHeader.OptionalHeader.SizeOfHeaders / ntNtHeader.OptionalHeader.SectionAlignment);
        lJumpSize += 1;
        lJumpSize *= (ntNtHeader.OptionalHeader.SectionAlignment);
    }
    lpImageMemoryDummy = (LPVOID)((long int)lpImageMemoryDummy + lJumpSize);

    // Copy Sections To Buffer
    for(lSectionCount = 0; lSectionCount < ntNtHeader.FileHeader.NumberOfSections; lSectionCount++)
    {
        lJumpSize = 0;
        lSectionSize = shSections[lSectionCount].SizeOfRawData;
        memcpy(lpImageMemoryDummy,
               (LPVOID)((long int)lpImage + shSections[lSectionCount].PointerToRawData),
               lSectionSize);
        if((shSections[lSectionCount].Misc.VirtualSize % ntNtHeader.OptionalHeader.SectionAlignment)==0)
        {
            lJumpSize = shSections[lSectionCount].Misc.VirtualSize;
        }
        else
        {
            lJumpSize  = (shSections[lSectionCount].Misc.VirtualSize /
                          ntNtHeader.OptionalHeader.SectionAlignment);
            lJumpSize += 1;
            lJumpSize *= (ntNtHeader.OptionalHeader.SectionAlignment);
        }
        lpImageMemoryDummy = (LPVOID)((long int)lpImageMemoryDummy + lJumpSize);
    }

    // Create Process
    if(pCmdLine == NULL)
    {
        cmdBufLen = strlen(pProcessName);
        pCmdLineBuf = (char *)malloc(cmdBufLen);
        if(pCmdLineBuf == NULL)
        {
            free(pProcessName);
            free(lpImageMemory);
            return FORK_PROC_ERR_MALLOC;
        }
        memset(pCmdLineBuf, 0x00, cmdBufLen);
        strcat(pCmdLineBuf, pProcessName);
    }
    else
    {
        cmdBufLen = strlen(pProcessName) + strlen(pCmdLine) + 10;
        pCmdLineBuf = (char *)malloc(cmdBufLen);
        if(pCmdLineBuf == NULL)
        {
            free(pProcessName);
            free(lpImageMemory);
            return FORK_PROC_ERR_MALLOC;
        }
        memset(pCmdLineBuf, 0x00, cmdBufLen);
        sprintf(pCmdLineBuf, "%s %s", pProcessName, pCmdLine);
    }

    if(pStartInfo == NULL || pProcInfo == NULL)
    {
        memset(&suStartUpInformation, 0x00, sizeof(STARTUPINFO));
        memset(&piProcessInformation, 0x00, sizeof(PROCESS_INFORMATION));
        suStartUpInformation.cb = sizeof(STARTUPINFO);
        pStartInfo = &suStartUpInformation;
        pProcInfo = &piProcessInformation;
    }

    if(CreateProcess(NULL, pCmdLineBuf, NULL, NULL, 1, CREATE_SUSPENDED,
                     NULL, NULL, pStartInfo, pProcInfo) == 0)
    {
        free(pProcessName);
        free(lpImageMemory);
        return FORK_PROC_ERR_CRE_PROC;
    }
    else
    {
        memset(&cContext, 0x00, sizeof(CONTEXT));
        cContext.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pProcInfo->hThread, &cContext);
    }

    // Check image base and image size
    if(lLocalImageBase == (long int)ntNtHeader.OptionalHeader.ImageBase && lImageSize <= lLocalImageSize)
    {
        VirtualProtectEx(pProcInfo->hProcess,
                         (LPVOID)((long int)ntNtHeader.OptionalHeader.ImageBase),
                         lImageSize, PAGE_EXECUTE_READWRITE,
                         (unsigned long*)&lPreviousProtection);
    }
    else
    {
        if(!NtUnmapViewOfSection(pProcInfo->hProcess, (LPVOID)((DWORD)lLocalImageBase)))
            VirtualAllocEx(pProcInfo->hProcess,
                           (LPVOID)((long int)ntNtHeader.OptionalHeader.ImageBase),
                           lImageSize,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    // Write Image to Process
    if(!WriteProcessMemory(pProcInfo->hProcess,
                           (LPVOID)((long int)ntNtHeader.OptionalHeader.ImageBase),
                           lpImageMemory, lImageSize, (unsigned long*)&lWritten))
    {
        free(pProcessName);
        free(lpImageMemory);
        free(pCmdLineBuf);
        return FORK_PROC_ERR_WR_MEM_IMG;
    }

    // Set Image Base
    if(!WriteProcessMemory(pProcInfo->hProcess, (LPVOID)((long int)cContext.Ebx + 8),
                           &ntNtHeader.OptionalHeader.ImageBase, 4, (unsigned long*)&lWritten))
    {
        free(pProcessName);
        free(lpImageMemory);
        free(pCmdLineBuf);
        return FORK_PROC_ERR_WR_MEM_CTX;
    }

    // Set the new entry point
    cContext.Eax = ntNtHeader.OptionalHeader.ImageBase + ntNtHeader.OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pProcInfo->hThread, &cContext);
    if(lLocalImageBase == (long int)ntNtHeader.OptionalHeader.ImageBase && lImageSize <= lLocalImageSize)
    {
        VirtualProtectEx(pProcInfo->hProcess,
                         (LPVOID)((long int)ntNtHeader.OptionalHeader.ImageBase),
                         lImageSize,
                         lPreviousProtection, 0);
    }

    // Resume the process
    ResumeThread(pProcInfo->hThread);
    if(pPid != NULL)
        *pPid = (int)pProcInfo->dwProcessId;
    if(phProc != NULL)
        *phProc = pProcInfo->hProcess;

    free(pProcessName);
    free(lpImageMemory);
    free(pCmdLineBuf);

    return FORK_PROC_SUCCESS;
}




