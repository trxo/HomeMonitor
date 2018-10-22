#ifndef WEBSOCKET_SERVER_FRAME_H
#define WEBSOCKET_SERVER_FRAME_H

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

std::string frameDecode(char *client_message);

int wsEncodeFrame(std::string inMessage, std::string &outFrame, enum WS_FrameType frameType);

bool doHandshake(char *client_message,int client_sock);

int sendMsg(std::string,int client_sock);


#endif WEBSOCKET_SERVER_FRAME_H
