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
#include "frame.h"
#include "epoll.h"

#define SERVER_PORT 8099
#define SERVER_SOCKET_PROT 8098
#define SERVER_IP "0.0.0.0"
#define BUF_SIZE 0xFFFF

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

       int listenfd = socket(AF_INET,fSOCK_STREAM,0);
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
   }


}

void webServer(){
    struct sockaddr_in server, client;
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

int sendMsg(std::string string, int client_sock) {
    std::string res;
    wsEncodeFrame(string, res, WS_TEXT_FRAME);
    return write(client_sock, res.c_str(), res.size());
}

bool doHandshake(char *client_message, int client_sock) {
    //handshake
    std::string response;

    std::string request = client_message;

    std::istringstream stream(request.c_str());

    std::string reqType;

    std::getline(stream, reqType);


    if (reqType != "GET / HTTP/1.1\r") {
        printf("handshake failed!\n");
        return false;
    }


    std::string header;
    std::string::size_type pos = 0;
    std::string websocketKey;

    while (std::getline(stream, header) && header != "\r") {
        header.erase(header.end() - 1);
        pos = header.find(":", 0);
        if (pos != std::string::npos) {
            std::string key = header.substr(0, pos);
            if (key == "Sec-WebSocket-Key") {
                std::string value = header.substr(pos + 2, header.size());
                websocketKey = value;
                break;
            }
        }
    }

    std::string accept = getKey(websocketKey);

    response = "HTTP/1.1 101 Switching Protocols\r\n";
    response += "Upgrade: websocket\r\n";
    response += "Connection: upgrade\r\n";
    response += "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
    write(client_sock, response.c_str(), response.size());
    return true;
}

/**
 * 获取websocket加密accept
 * @param key
 * @return
 */
std::string getKey(std::string key) {
    //key + mask
    const std::string input = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    SHA1 checksum;
    checksum.update(input);
    std::string hash = checksum.final();
    //获取二进制流
    std::string str = HexToBin(hash);
    return base64_encode(reinterpret_cast<const unsigned char *>(str.c_str()), str.length());
}

/**
 * 十六进制转换为二进制
 * @param strHex
 * @return
 */
std::string HexToBin(const std::string &strHex) {
    if (strHex.size() % 2 != 0) {
        return "";
    }

    std::string strBin;
    strBin.resize(strHex.size() / 2);
    for (size_t i = 0; i < strBin.size(); i++) {
        uint8_t cTemp = 0;
        for (size_t j = 0; j < 2; j++) {
            char cCur = strHex[2 * i + j];
            if (cCur >= '0' && cCur <= '9') {
                cTemp = (cTemp << 4) + (cCur - '0');
            } else if (cCur >= 'a' && cCur <= 'f') {
                cTemp = (cTemp << 4) + (cCur - 'a' + 10);
            } else if (cCur >= 'A' && cCur <= 'F') {
                cTemp = (cTemp << 4) + (cCur - 'A' + 10);
            } else {
                return "";
            }
        }
        strBin[i] = cTemp;
    }

    return strBin;
}

std::string frameDecode(char *client_message) {
//    std::cout << "frameDecode" << std::endl;
//    std::cout << client_message << std::endl;
//    std::cout << "Fin: "<< (client_message[0] & 0x80) << std::endl;
//    std::cout << "opCode: "<< (client_message[0] & 0x0F) << std::endl;
//    std::cout << "Mask: "<< (client_message[1] & 0x80) << std::endl;
//    std::cout << "payload_len: "<< (client_message[1] & 0x7F) << std::endl;

    uint8_t payloadFieldExtraBytes;
    uint16_t payloadLength = client_message[1] & 0x7F;

    if (payloadLength == 126) {
        payloadFieldExtraBytes = 2;

    } else if (payloadLength == 127) {
        payloadFieldExtraBytes = 8;

    } else {
        payloadFieldExtraBytes = 0;
    }


    // header: 2byte, masking key: 4byte
    const char *maskingKey = &client_message[2 + payloadFieldExtraBytes];
    char *payloadData = new char[payloadLength + 1];
    memset(payloadData, 0, payloadLength + 1);
    memcpy(payloadData, &client_message[2 + payloadFieldExtraBytes + 4], payloadLength);
    for (int i = 0; i < payloadLength; i++) {
        payloadData[i] = payloadData[i] ^ maskingKey[i % 4];
    }
    return payloadData;
}


int wsEncodeFrame(std::string inMessage, std::string &outFrame, enum WS_FrameType frameType) {
    int ret = WS_EMPTY_FRAME;
    const uint32_t messageLength = inMessage.size();
    if (messageLength > 32767) {
        // 暂不支持这么长的数据
        return WS_ERROR_FRAME;
    }

    uint8_t payloadFieldExtraBytes = (messageLength <= 0x7d) ? 0 : 2;
    // header: 2字节, mask位设置为0(不加密), 则后面的masking key无须填写, 省略4字节
    uint8_t frameHeaderSize = 2 + payloadFieldExtraBytes;
    uint8_t *frameHeader = new uint8_t[frameHeaderSize];
    memset(frameHeader, 0, frameHeaderSize);
    // fin位为1, 扩展位为0, 操作位为frameType
    frameHeader[0] = static_cast<uint8_t>(0x80 | frameType);

    // 填充数据长度
    if (messageLength <= 0x7d) {
        frameHeader[1] = static_cast<uint8_t>(messageLength);
    } else {
        frameHeader[1] = 0x7e;
        uint16_t len = htons(messageLength);
        memcpy(&frameHeader[2], &len, payloadFieldExtraBytes);
    }

    // 填充数据
    uint32_t frameSize = frameHeaderSize + messageLength;
    char *frame = new char[frameSize + 1];
    memcpy(frame, frameHeader, frameHeaderSize);
    memcpy(frame + frameHeaderSize, inMessage.c_str(), messageLength);
    frame[frameSize] = '\0';
    outFrame = frame;

    delete[] frame;
    delete[] frameHeader;
    return ret;
}

