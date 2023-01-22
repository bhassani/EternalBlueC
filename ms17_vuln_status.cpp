#include <stdio.h>
#include <windows.h>
#include <winsock.h>
#include <tchar.h>
#pragma comment(lib, "wsock32.lib")

unsigned char SmbNegociate[] =
"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x00"
"\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"
"\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30"
"\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";

unsigned char Session_Setup_AndX_Request[] =
"\x00\x00\x00\x88\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc0\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00"
"\x0d\xff\x00\x88\x00\x04\x11\x0a\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00"
"\x00\x00\x00\x00\x00\xd4\x00\x00\x00\x4b\x00\x00\x00\x00\x00\x00\x57\x00"
"\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00"
"\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00\x57\x00"
"\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00"
"\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00";

unsigned char treeConnectRequest[] = 
"\x00\x00\x00\x60\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x18\x07\xc0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
"\x00\x08\x40\x00\x04\xff\x00\x60\x00\x08\x00\x01\x00\x35\x00\x00"
"\x5c\x00\x5c\x00\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00"
"\x38\x00\x2e\x00\x31\x00\x37\x00\x35\x00\x2e\x00\x31\x00\x32\x00"
"\x38\x00\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x3f\x3f\x3f\x3f\x3f\x00";

unsigned char transNamedPipeRequest[] = 
"\x00\x00\x00\x4a\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x01\x28\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x8e\xa3\x01\x08"
"\x52\x98\x10\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x4a\x00\x02\x00\x23\x00\x00"
"\x00\x07\x00\x5c\x50\x49\x50\x45\x5c\x00";

unsigned char recvbuff[2048];

int main(int argc, char** argv)
{
    WSADATA    ws;
    struct sockaddr_in server;
    SOCKET    sock;
    DWORD    ret;

    WSAStartup(MAKEWORD(2, 2), &ws);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock <= 0)
    {
        return 0;
    }
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(argv[1]);
    server.sin_port = htons((USHORT)445);
    printf("Connecting...\n");
    ret = connect(sock, (struct sockaddr*) & server, sizeof(server));
    if (ret == -1)
    {
        printf("Connection Error, Port 445 Firewalled?\n");
        return 0;
    }
    
    //send SMB negociate packet
    send(sock, (char*)SmbNegociate, sizeof(SmbNegociate) - 1, 0);
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //send Session Setup AndX request
    printf("sending Session_Setup_AndX_Request!\n");
    ret = send(sock, (char*)Session_Setup_AndX_Request, sizeof(Session_Setup_AndX_Request) - 1, 0);
    if (ret <= 0)
    {
        printf("send Session_Setup_AndX_Request error!\n");
        return 0;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);
    
    //output windows version to the screen
	printf("Remote OS: ");
	int r;
	for (r = 0; r < 39; r++) {
		printf("%c", recvbuff[44 + r]);
	}
	printf("\n");
    
    char userid[2];
    char treeid[2];
    //copy userID from recvbuff @ 32,33
    userid[0] = recvbuff[32];
    userid[1] = recvbuff[33];
    
    //update userID in the tree connect request
    treeConnectRequest[32] = userid[0];
    treeConnectRequest[33] = userid[1];

    //send TreeConnect request
    printf("sending TreeConnect Request!\n");
    ret = send(sock, (char*)treeConnectRequest, sizeof(treeConnectRequest) - 1, 0);
    if (ret <= 0)
    {
        printf("send TreeConnect_AndX_Request error!\n");
        return 0;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //copy treeID from recvbuff @ 28, 29
    treeid[0] = recvbuff[28];
    treeid[1] = recvbuff[29];
    //update treeid & userid in the transNamedPipe Request
    transNamedPipeRequest[28] = treeid[0];
    transNamedPipeRequest[29] = treeid[1];
    transNamedPipeRequest[32] = userid[0];
    transNamedPipeRequest[33] = userid[1];

    //send transNamedPipe request
    printf("sending transNamedPipeRequest!\n");
    ret = send(sock, (char*)transNamedPipeRequest, sizeof(transNamedPipeRequest) - 1, 0);
    if (ret <= 0)
    {
        printf("send modified transNamedPipeRequest error!\n");
        return 0;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //compare the NT_STATUS response to 0xC0000205 ( STATUS_INSUFF_SERVER_RESOURCES)
    if (recvbuff[9] == 0x05 && recvbuff[10] == 0x02 && recvbuff[11] == 0x00 && recvbuff[12] == 0xc0)
    {
        printf("vulnerable to MS17-010\n");
    }
    else {
        printf("not vulnerable to MS17-010\n");
    }
    
    //cleanup
    closesocket(sock);
    WSACleanup();
    return 0;
}
