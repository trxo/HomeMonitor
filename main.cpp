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

#define SERVER_PORT 8099
#define SERVER_IP "127.0.0.1"
#define BUF_SIZE 0xFFFF


int main(int argc, char *argv[]) {

    struct sockaddr_in server, client;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(SERVER_IP);
    server.sin_port = htons(SERVER_PORT);

    //create socket
    int socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc < 0) {
        perror("Cound not create socket!");
        exit(-1);
    }

    //bind
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

    printf("the server start listen at: %s:%d\n",SERVER_IP,SERVER_PORT);



    socklen_t socket_len = sizeof(struct sockaddr_in);

    //accept
    int client_sock = accept(socket_desc, (struct sockaddr *) &client, (socklen_t *) &socket_len);

    if (client_sock < 0) {
        perror("accept error.");
        exit(-1);
    }

    //handshake
    bool handshake = false;

    ssize_t read_size;
    char buffer[BUF_SIZE];
    bzero(buffer,BUF_SIZE);

    while ((read_size = recv(client_sock, buffer, BUF_SIZE, 0)) > 0) {

        if (!handshake) {
            handshake = doHandshake(buffer,client_sock);
            if(!handshake){
                perror("handshake error");
                exit(-1);
            }
        } else {
            std::string res_str = frameDecode(buffer);
            printf("recv data from client:%s\n",res_str.c_str());
            sendMsg(res_str,client_sock);
        }
        bzero(buffer,BUF_SIZE);
    }
    if (read_size == 0) {
        printf("Client disconnected.\n");
    } else if (read_size == -1) {
        perror("recv failed.");
    }
    close(socket_desc);
    return 0;
}

int sendMsg(std::string string,int client_sock){
    std::string res;
    wsEncodeFrame(string, res,WS_TEXT_FRAME);
    return write(client_sock, res.c_str(), res.size());
}

bool doHandshake(char *client_message,int client_sock)
{
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


int wsEncodeFrame(std::string inMessage, std::string &outFrame, enum WS_FrameType frameType)
{
    int ret = WS_EMPTY_FRAME;
    const uint32_t messageLength = inMessage.size();
    if (messageLength > 32767)
    {
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
    if (messageLength <= 0x7d)
    {
        frameHeader[1] = static_cast<uint8_t>(messageLength);
    }
    else
    {
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

