#include <stdio.h>
#include <string.h>     //strlen
#include <sys/socket.h>
#include <arpa/inet.h>  //inet_addr
#include <unistd.h>     //write
#include <iostream>
#include <sstream>
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"

using namespace CryptoPP;


std::string getKey(std::string);

std::string HexToBin(const std::string &strHex);

std::string frameDecode(char *client_message);

void frameEncode(std::string, std::string &outFrame);

void handshake(bool &handshake);

enum WS_Status {
    WS_STATUS_CONNECT = 0,
    WS_STATUS_UNCONNECT = 1,
};

enum WS_FrameType {
    WS_EMPTY_FRAME = 0xF0,
    WS_ERROR_FRAME = 0xF1,
    WS_TEXT_FRAME = 0x01,
    WS_BINARY_FRAME = 0x02,
    WS_PING_FRAME = 0x09,
    WS_PONG_FRAME = 0x0A,
    WS_OPENING_FRAME = 0xF3,
    WS_CLOSING_FRAME = 0x08
};


int main(int argc, char *argv[]) {

    int socket_desc, client_sock, c, read_size;
    struct sockaddr_in server, client;
    char client_message[2000];

    //Create socket

    socket_desc = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_desc == -1) {
        printf("Cound not create socket!");
    }

    puts("Socket Created.");

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(8777);

    //Bind
    if (bind(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0) {
        perror("bind failed.");
        return 1;
    }

    puts("bind done.");

    //listen
    listen(socket_desc, 3);

    //Accept and incomming connection
    puts("Waiting for incomming connections...");
    c = sizeof(struct sockaddr_in);

    //accept connection from a incomming client
    client_sock = accept(socket_desc, (struct sockaddr *) &client, (socklen_t *) &c);

    if (client_sock < 0) {
        perror("accept error.");
        return 1;
    }

    puts("Connection accepted...");

    //握手标示
    bool handshake = false;

    //Recevied message from client
    while ((read_size = recv(client_sock, client_message, 2000, 0)) > 0) {
        if (!handshake) {
            std::cout << "do handshake..." << std::endl;
            //handshake
            std::string response;

            std::string request = client_message;

            std::istringstream stream(request.c_str());

            std::string reqType;

            std::getline(stream, reqType);


            if (reqType != "GET / HTTP/1.1\r") {
                std::cout << "handshake failed!" << std::endl;
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
            response += "Sec-WebSocket-Accept: ";
            response += accept + "\r\n";

            write(client_sock, response.c_str(), response.size());

            handshake = true;

        } else {

            std::string res_str;

            res_str = frameDecode(client_message);

            //将该消息回送客户端

            std::string res;

            frameEncode(res_str, res);

            write(client_sock, res.c_str(), res.size());


        }

        usleep(10);
    }

    if (read_size == 0) {
        puts("Client disconnected.");
        fflush(stdout);
    } else if (read_size == -1) {
        perror("recv failed.");
    }

    return 0;

}

/**
 * 获取websocket加密key
 * @param key
 * @return
 */
std::string getKey(std::string key) {
    //std::cout << key << std::endl;
    SHA1 sha1;
    std::string dst;
    std::string base;
    std::string mask = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    StringSource(key + mask, true, new HashFilter(sha1, new HexEncoder(new StringSink(dst))));

    //std::cout << dst << std::endl;

    StringSource(HexToBin(dst), true, new Base64Encoder(new StringSink(base)));

    return base;
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

    //printf("%d", payloadFieldExtraBytes);

    // header: 2字节, masking key: 4字节
    const char *maskingKey = &client_message[2 + payloadFieldExtraBytes];
    char *payloadData = new char[payloadLength + 1];
    memset(payloadData, 0, payloadLength + 1);
    memcpy(payloadData, &client_message[2 + payloadFieldExtraBytes + 4], payloadLength);
    for (int i = 0; i < payloadLength; i++) {
        payloadData[i] = payloadData[i] ^ maskingKey[i % 4];
    }
    //std::string abc = payloadData;
    //std::cout << payloadData << std::endl;
    return payloadData;
}

void frameEncode(std::string msg, std::string &outFrame) {
    uint32_t messageLength = msg.size();
    std::cout << "messageLength: " << messageLength << std::endl;

    uint8_t payloadFieldExtraBytes = (messageLength <= 0x7d) ? 0 : 2;

    //std::cout << "payloadFieldExtraBytes:";
    //printf("%d\n",payloadFieldExtraBytes);


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

void handshake(bool &handshake) {

}
// 1.                                   websocket协议
//      websocket约定了一个通信的规范，通过一个握手的机制，客户端（浏览器）和服务器（webserver）之间能建立一个类似tcp
// 的连接，从而方便c/s之间的实时通信。在websocket出现之前，web交互一般是基于http协议的短连接或者长连接。
//2.                                    websocket初始握手
//      websocket的连接始于一个HTTP请求。该请求和其他请求很相似，但是包含一个特殊的首标————Upgrade，它表示客户端将把
// 连接升级到websocket协议，以下是客户端和服务端的握手示例
//
// 客户端发起的HTTP请求:
// ——————————————————————————————————————————————————————————————————————————————————————————
//     GET / HTTP/1.1
//     Host: 127.0.0.1
//     Origin: file://
//     Sec-Websocket-Key:
//     Sec-Websocket-Version: 13
//     Upgrade: websocket
// ——————————————————————————————————————————————————————————————————————————————————————————
//
//
//服务端发起的HTTP响应
// ——————————————————————————————————————————————————————————————————————————————————————————
//     101 Switching Protocols
//     Connection: Upgrade
//     Date:
//     Sec-Websocket-Accept:
//     Server:
//     Upgrade: websocket
// ——————————————————————————————————————————————————————————————————————————————————————————
//
//服务端响应101代码，Upgrade首标和正确的Sec-WebSocket-Accept首标后，建立连接，否则连接不能成功。成功升级后，连接的语法
// 切换为用于表示WebSocket消息的数据帧格式。
//                                     消息格式
//
//  websocket帧头

//      Websockets use hybi10 frame encoding:
//
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-------+-+-------------+-------------------------------+
//      |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//      |I|S|S|S|  (4)  |A|     (7)     |             (16/63)           |
//      |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//      | |1|2|3|       |K|             |                               |
//      +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//      |     Extended payload length continued, if payload len == 127  |
//      + - - - - - - - - - - - - - - - +-------------------------------+
//      |                               |Masking-key, if MASK set to 1  |
//      +-------------------------------+-------------------------------+
//      | Masking-key (continued)       |          Payload Data         |
//      +-------------------------------- - - - - - - - - - - - - - - - +
//      :                     Payload Data continued ...                :
//      + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//      |                     Payload Data continued ...                |
//      +---------------------------------------------------------------+
//
//      +----------+----------+
//      |   操作码  | mask1bit |
//      |          | 长度7bit  |
//      +----------+----------+