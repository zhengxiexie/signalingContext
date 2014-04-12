#ifndef _SSNET_H
#define _SSNET_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <iostream>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <utime.h>

//#include <map>
#include <set>
//#include <vector>
//#include <string>

using namespace std;


extern int field_imsi_num;
extern int field_event_type_num;
extern int field_time_stamp_num;
extern int field_duration_num;
extern int field_lac_id_num;
extern int field_ci_id_num;
extern int field_cause_num;
extern int field_other_party_num;

extern int field_local_prov_flag_num;
extern int field_prov_code_num;
extern int field_city_code_num;

extern pthread_mutex_t		pthread_logfile_mutex;

extern int		file_read_exitflag;


extern LineBuff 	lb;
extern unsigned int	ss_num;
extern int		exitflag;


void *produce_fr_tcp(void *arg);
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

#endif
