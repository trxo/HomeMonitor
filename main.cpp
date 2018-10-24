#include <stdio.h>
#include <string.h>     //strlen
#include <sys/socket.h>
#include <arpa/inet.h>  //inet_addr
#include <unistd.h>     //write
#include <iostream>
#include <sstream>
#include "base64/base64.cpp"
#include "sha1/sha1.cpp"
#include <fstream>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <list>
#include <map>
#include <wait.h>
#include "config.h"
#include "websocekt.h"
#include "epoll.h"

std::map<int,bool> clients_map;
void webServer();
int main(int argc, char *argv[]) {

   int pid = fork();
   if(pid < 0 ){
       perror("fork error!");
   }else if (pid == 0){
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

void webServer(){
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(SERVER_IP);
    server.sin_port = htons(SERVER_PORT);

    //create socket
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
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

    int epfd = epoll_create(EPOLL_SIZE);
    if (epfd < 0) {
        perror("epoll create error!");
        exit(-1);
    }

    printf("epoll create, epfd:%d\n", epfd);

    static struct epoll_event events[EPOLL_SIZE];
    addfd(epfd, listenfd, true);

    char buffer[BUF_SIZE];
    while (1) {
        int epoll_event_count = epoll_wait(epfd, events, EPOLL_SIZE, -1);
        if (epoll_event_count < 0) {
            perror("epoll wait error!");
            break;
        }
        for (int i = 0; i < epoll_event_count; ++i) {
            int sockfd = events[i].data.fd;
            if (sockfd == listenfd) {
                struct sockaddr_in client_address;
                socklen_t client_addr_length = sizeof(struct sockaddr_in);
                int clientfd = accept(listenfd, (struct sockaddr *) &client_address, &client_addr_length);
                printf("client connectiong from: %s : %d (IP:PORT),client = %d\n", inet_ntoa(client_address.sin_addr),
                       ntohs(client_address.sin_port), clientfd);
                addfd(epfd, clientfd, true);
                clients_map[clientfd] = false;
                printf("Add new clientfd = %d to epoll\n",clientfd);
                printf("Now there are %d clients in the chat room\n",(int)clients_map.size());
            }else{
                bzero(buffer,BUF_SIZE);
                ssize_t read_size = recv(sockfd, buffer, BUF_SIZE, 0);

                //close
                if(read_size == 0){
                    printf("clientfd %d close connections \n",sockfd);
                    close(sockfd);
                    continue;
                }

                //error
                if(read_size < 0){
                    printf("recv msg from clientfd %d failed\n",sockfd);
                    close(sockfd);
                    continue;
                }

                //handshank
                if(!clients_map[sockfd]){
                    if(doHandshake(buffer,sockfd)){
                        clients_map[sockfd] = true;
                    } else{
                        clients_map.erase(sockfd);
                        close(sockfd);
                    }
                } else {  //frame data
                    std::string recv_msg = frameDecode(buffer);
                    printf("recv clientfd :%d msg :%s\n",sockfd,recv_msg.c_str());
                }
            }
        }
    }
}
