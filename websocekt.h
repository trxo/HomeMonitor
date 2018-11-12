#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <iostream>
#include <unistd.h>
#include <string.h>
#include "sha1/sha1.cpp"
#include "base64/base64.cpp"
#include <arpa/inet.h>  //inet_addr

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


std::string getKey(std::string);

std::string HexToBin(const std::string &strHex);

std::string wsDecodeFrame(char *client_message);

int wsEncodeFrame(std::string inMessage, std::string &outFrame, enum WS_FrameType frameType);

bool doHandshake(char *client_message,int client_sock);

int sendMsg(std::string,int client_sock);



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

std::string wsDecodeFrame(char *buffer) {

//    std::cout << "Fin: "<< (buffer[0] & 0x80) << std::endl;
//    std::cout << "opCode: "<< (buffer[0] & 0x0F) << std::endl;
//    std::cout << "Mask: "<< (buffer[1] & 0x80) << std::endl;
//    std::cout << "payload_len: "<< (buffer[1] & 0x7F) << std::endl;

    uint8_t payloadFieldExtraBytes;
    uint16_t payloadLength = buffer[1] & 0x7F;

    switch (payloadLength) {
        case 126:
            payloadFieldExtraBytes = 2;
            break;
        case 127:
            payloadFieldExtraBytes = 8;
            break;
        default:
            payloadFieldExtraBytes = 0;
    }
    // header: 2byte, masking key: 4byte
    const char *maskingKey = &buffer[2 + payloadFieldExtraBytes];
    char *payloadData = new char[payloadLength + 1];
    memset(payloadData, 0, payloadLength + 1);
    memcpy(payloadData, &buffer[2 + payloadFieldExtraBytes + 4], payloadLength);
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

#endif WEBSOCKET_H
