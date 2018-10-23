#include <sys/epoll.h>
#include <fcntl.h>

//epoll size
#define EPOLL_SIZE 1000



/**
 * set no block
 * @param sockfd
 * @return
 */
int setnonblock(int sockfd)
{
    fcntl(sockfd,F_SETFL,fcntl(sockfd,F_GETFD,0) | O_NONBLOCK);
    return 0;
}
/**
 * add epoll
 * @param epollfd
 * @param fd
 * @param enable_et
 */
void addfd(int epollfd,int fd, bool enable_et){
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = EPOLLIN;
    if(enable_et){
        ev.events = EPOLLIN | EPOLLET;
    }
    epoll_ctl(epollfd,EPOLL_CTL_ADD,fd,&ev);
    setnonblock(fd);
}

