#ifndef _SSNET_H
#define _SSNET_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

//#include <map>
#include <set>
//#include <vector>
//#include <string>

using namespace std;


extern LineBuff 	lb;
extern unsigned int	ss_num;
extern int		exitflag;

extern int		file_read_exitflag;

void *produce_fr_tcp(void *arg);
//void *load_timer(void *arg);
void *produce_fr_udp(void *arg);
int Getaddrinfo(char *hostname,char *servname,struct addrinfo *hints,struct addrinfo **res);
int Getnameinfo(struct sockaddr *sa, socklen_t salen,char *host,size_t hostlen,char *serv,size_t servlen,int flags);
struct hostent *Gethostbyname(const char *hname );
int Socket(int family, int type, int protocol);
int Bind(int fd, const struct sockaddr *sockaddr, int size);
int Accept(int fd, struct sockaddr *sockaddr, socklen_t *addrlen);
int Connect(int fd, struct sockaddr *sockaddr, socklen_t addrlen);
int Setsockopt(int s, int level, int optname, void  *optval, socklen_t optlen);

void *produce_fr_ftp(void *arg);
int sortSignal(SignalIndex *signalIndex,char * imsi,time_t sec, char * line);
int get_input_file_path(char *input_file_path);
int get_input_file_backup_path(char *input_file_backup_path);
int get_sleep_interval();


#endif
