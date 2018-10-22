#include <stdio.h>
#include <string.h>     //strlen
#include <sys/socket.h>
#include <arpa/inet.h>  //inet_addr
#include <unistd.h>     //write
#include <iostream>
#include <sstream>
#include "frame.h"
#include "base64/base64.cpp"
#include "sha1/sha1.cpp"
#include <fstream>
#include <unistd.h>


#define BUF_SIZE 0xFFFF
int main(int argc, char *argv[]) {

    int socket_desc, client_sock, c;
    struct sockaddr_in server, client;
    char buffer[BUF_SIZE];
    bzero(buffer,BUF_SIZE);
    //Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        perror("Cound not create socket!");
        exit(-1);
    }
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(8089);

    //Bind
    if (bind(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0) {
        perror("bind failed.");
        exit(-1);
    }

    //listen
    int ret = listen(socket_desc, 3);
    if(ret < 0){
        perror("listen failed.");
        exit(-1);
    }

    //Accept and incomming connection
    printf("Waiting for incomming connections...\n");

    c = sizeof(struct sockaddr_in);

    //accept connection from a incomming client
    client_sock = accept(socket_desc, (struct sockaddr *) &client, (socklen_t *) &c);

    if (client_sock < 0) {
        perror("accept error.");
        exit(-1);
    }

    printf("Connection accepted...\n");

    //握手标示
    bool handshake = false;

    ssize_t read_size;
    //Recevied message from client
    while ((read_size = recv(client_sock, buffer, 2000, 0)) > 0) {

        printf("client_message size is: %d\n",read_size);
        if (!handshake) {
            handshake = doHandshake(buffer,client_sock);
            printf("handshake success...\n");
        } else {
            std::string res_str = frameDecode(buffer);
            printf("recv data from client:%s\n",res_str.c_str());
            //将该消息回送客户端
            sendMsg(res_str,client_sock);

        }
        memset(buffer,0, sizeof(buffer));
        bzero(buffer,BUF_SIZE);
    }

    if (read_size == 0) {
        printf("Client disconnected.\n");
        fflush(stdout);
    } else if (read_size == -1) {
        perror("recv failed.");
    }
    return 0;
}

int sendMsg(std::string string,int client_sock){
    std::string res;
    frameEncode(string, res);
    return write(client_sock, res.c_str(), res.size());
}

bool doHandshake(char *client_message,int client_sock)
{
    printf("do handshake...\n");
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
    char p[2000];
    response.copy(p, response.size(), 0);
    *(p + response.size()) = '/0'; //要手动加上结束符
    write(client_sock, p, strlen(p));
//    write(client_sock, response.c_str(), response.size());

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
    return base64_encode(reinterpret_cast<const unsigned char*>(str.c_str()),str.length());
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


    // header: 2字节, masking key: 4字节
    const char *maskingKey = &client_message[2 + payloadFieldExtraBytes];
    std::cout << "maskingKey:" << std::endl;
    std::cout << maskingKey << std::endl;
    char *payloadData = new char[payloadLength + 1];
    memset(payloadData, 0, payloadLength + 1);
    memcpy(payloadData, &client_message[2 + payloadFieldExtraBytes + 4], payloadLength);
    for (int i = 0; i < payloadLength; i++) {
        payloadData[i] = payloadData[i] ^ maskingKey[i % 4];
    }
    return payloadData;
}

void frameEncode(std::string msg, std::string &outFrame) {
    uint32_t messageLength = msg.size();
    printf("messageLength: %d\n",messageLength);

    uint8_t payloadFieldExtraBytes = (messageLength <= 0x7d) ? 0 : 2;

    uint8_t frameHeaderSize = 2 + payloadFieldExtraBytes;

    uint8_t *frameHeader = new uint8_t[frameHeaderSize];

    memset(frameHeader, 0, frameHeaderSize);

    frameHeader[0] = static_cast<uint8_t>(0x80 | WS_TEXT_FRAME);

    frameHeader[1] = static_cast<uint8_t>(messageLength);


    uint32_t frameSize = frameHeaderSize + messageLength;

    //printf("frameSize: %d\n",frameSize);

    char *frame = new char[frameSize + 1];

    memcpy(frame, frameHeader, frameHeaderSize);

    memcpy(frame + frameHeaderSize, msg.c_str(), messageLength);

    frame[frameSize] = '\0';


    outFrame = frame;

    delete[] frame;
    delete[] frameHeader;
}

