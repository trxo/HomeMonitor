#include <stdio.h>
#include <string.h>     //strlen
#include <sys/socket.h>
#include <arpa/inet.h>  //inet_addr
#include <sstream>
#include <fstream>
#include <sys/epoll.h>
#include <fcntl.h>
#include <list>

#include <wait.h>
#include "websocekt.h"

int main(int argc, char *argv[]) {
   int pid = fork();
   if(pid < 0 ){
       perror("fork error!");
   }else if (pid == 0){
       //child
       webServer();
   }else{
       struct sockaddr_in server;
       server.sin_family = AF_INET;
       server.sin_addr.s_addr = inet_addr(SERVER_IP);
       server.sin_port = htons(SERVER_SOCKET_PROT);

       int listenfd = socket(AF_INET,SOCK_STREAM,0);
       if (listenfd < 0) {
           perror("Cound not create socket!");
           exit(-1);
       }
       //bind
       if (bind(listenfd, (struct sockaddr *) &server, sizeof(server)) < 0) {
           perror("bind failed.");
           exit(-1);
       }

       //listen
       int ret = listen(listenfd, 3);
       if (ret < 0) {
           perror("listen failed.");
           exit(-1);
       }

       printf("the server start listen at: %s:%d\n", SERVER_IP, SERVER_PORT);
       wait(NULL);
   }
}


