#ifndef _SSPUBLIC_H
#define _SSPUBLIC_H


#include <sys/types.h>
#include <sys/wait.h>
#include <sys/times.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <time.h>
#include <dirent.h>
#include <pthread.h>

#include <iostream>
#include <string>

//#define _ORACLE_ 8
//#define		_DB2_	7		

#define		FBUFFSIZE	32768		
#define		LBSIZE		2097152		
#define		MAXLINE		200 //128

#define		BIG_MAXLINE	1024

#define		MAX_BCD_IMSI_LEN	8
#define		IMSI_LEN	15

//设置从数据库中读取数据的最大缓冲行数
#define		MAX_EXTRACT_ROW	10000

//设置最大的手机号码前缀数 
#define		MAX_MOBILE_PREFIX_NUM	50

//设置在BCDContext中对段号码的最大存储长度，当超过此长度时，对上下文的信息输出，
//最大不能超过100字节!!!!!!!!! 因为load中的表相关字段就设置了100个字节
//建议采用25个字节的配置
//保证内存的的最大使用量，对此值的调整，会影响初始化时分配的内存大小
//#define		MAX_OTHER_NUMBERS_LEN	30	// 没啥情况，不要轻易动
#define		MAX_OTHER_NUMBERS_LEN	50	// 没啥情况，不要轻易动


//最大不能超过30字节!!!!!!!!! 因为load中的表相关字段就设置了30个字节
#define		MAX_AREA_LEN	10	// 没啥情况，不要轻易动

#define		MAX_AREA_LEN	10	// 没啥情况，不要轻易动

#define		MAX_LAST_ACTION_TYPE_LEN	11	// 没啥情况，不要轻易动
#define		MAX_CAUSE_LEN	5	// 没啥情况，不要轻易动

#define		MAX_PROV_CODE_LEN	5	// 没啥情况，不要轻易动
#define		MAX_CITY_CODE_LEN	6	// 没啥情况，不要轻易动
#define		MAX_LOCAL_PROV_FLAG_LEN	2	// 没啥情况，不要轻易动

// 当初始化时，设置需要加载的用户上下文信息
// 目前情况，每次初始化时，不加载以前用户信息
#define		RESTORE_FILE_NAME "../data/context.txt"

#define		MAX_LOAD_FILE_NUM 10

#define		BACKUP_FILE_PREFIX "../output/out_bak/backup_context"

// 设置省份，以区分不同省市接口不同
//#define		PROVINCE	"beijing"

#define  max(A, B) ((A) > (B) ? (A) : (B))
#define  min(A, B) ((A) > (B) ? (B) : (A))


typedef struct {
	char receive_port[16];
	int direct_receive;
	unsigned int analyze_thread_num;
	unsigned int load_file_num;	
	char monitor_host[32];
	char monitor_port[16];
	unsigned int monitor_interval;
	unsigned int load_interval;
	int hash_tune;
	unsigned int context_capacity;
	char db_name[16];
	char db_user[16];
	char db_passwd[16];
	char table_name[51];
	char select_cond[101];
	unsigned int autosave_slice; 
	unsigned int slice_num; 
	int init_context_period; 
	unsigned int init_context_day; 		
	unsigned int init_context_hour; 
	unsigned int init_context_min; 
	unsigned int backup_context_interval;

	char physical_area_table_name[51];
	char physical_area_table_cel[21];

	char msisdn_info_table_name[51];
	char pstn_area_info_table_name[51];
	char numbers_prefix_info_table_name[51];
	
	char mobile_prefix_table_name[51];
		
	unsigned int resident_time_raft;
	unsigned int resident_time_interval;
	
	char load_file_prefix[201];
	char output_file_suffix[50];	
	
	char nonparticipant_file_path[201];

	char input_file_path[201];
	char input_file_backup_path[201];
	unsigned int sleep_interval;
				
	int event_type_filter;
	int imsi_msisdn_flag;
	int agg_cell_flag;

	char local_prov_code[MAX_PROV_CODE_LEN];
	int other_prov_flag;
	
	int signal_sort_flag;
	int signal_sort_capacity;
	int signal_sort_interval;
	
	char log_file_path[201];
	char err_file_path[201];
	char proc_file_path[201];			
	char host_code[21];
	char entity_type_code[21];
	char entity_sub_code[21];
	int  log_interval;	
	char filename[100];				
} Config;

//extern Config *cfg;

typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t  more;
	pthread_cond_t  less;
	int empty;
	int to;
	int from;
	int lines;
	char buf[LBSIZE];
}LineBuff;


typedef struct {
	int num;			
	int from;			
	char buf[FBUFFSIZE];
} FileBuff;


typedef struct {
	pthread_mutex_t	mutex[MAX_LOAD_FILE_NUM];
	char *fbuf;				
	size_t num[MAX_LOAD_FILE_NUM];		
	int	counts[MAX_LOAD_FILE_NUM];			
	char fname[MAX_LOAD_FILE_NUM][500];		
	char tabname[MAX_LOAD_FILE_NUM][200];	
	int fd[MAX_LOAD_FILE_NUM];			
	int timeout[MAX_LOAD_FILE_NUM];
	time_t event_time_begin[MAX_LOAD_FILE_NUM];					
} Analyze;


typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	unsigned int context_capacity;
	unsigned int context_capacity_used;	
	unsigned int redirect_capacity;
	unsigned int conflict_num;
	int hash_tune;	
	unsigned int analyze_thread_num;
	unsigned int load_file_num;
	int direct_receive;
	char table_name[51];
	char select_cond[101];
	int init_context_period; 
	unsigned int init_context_day; 		
	unsigned int init_context_hour; 
	unsigned int init_context_min; 
	unsigned int backup_context_interval;

	char physical_area_table_name[51];
	char physical_area_table_cel[21];

	//设置停留时间的阀值
	unsigned int resident_time_raft;
	unsigned int resident_time_interval;

	//设置输出话单文件路径与文件名前缀配置
	char load_file_prefix[201];
	char output_file_suffix[50];	
		
	//# 当采用Socket方式时，设置读取程序停止期间产生的信令文件的路径
	char nonparticipant_file_path[201];

	char input_file_path[201];
	char input_file_backup_path[201];
	unsigned int sleep_interval;
		
	int event_type_filter;
	int imsi_msisdn_flag;
	int agg_cell_flag;
	
	char msisdn_info_table_name[51];
	char pstn_area_info_table_name[51];
	char numbers_prefix_info_table_name[51];
	
	char mobile_prefix_table_name[51];

	char local_prov_code[MAX_PROV_CODE_LEN];
	int other_prov_flag;
	
	int signal_sort_flag;
	int signal_sort_capacity;
	int signal_sort_interval;

	char log_file_path[201];	
	char err_file_path[201];
	char proc_file_path[201];				
	char host_code[21];
	char entity_type_code[21];
	char entity_sub_code[21];
	
	int  log_interval;
	
	char filename[100];					
} Check;

extern Check chk;

typedef struct content{
	time_t event_time;
	char line[MAXLINE];
	struct content *next;
}SignalContent;

typedef struct {
	SignalContent * head;
} SignalIndex;

typedef struct {
	time_t signal_time;
	SignalIndex * index;
} SignaltimeIndex;

int Discard(char *line,int flds);
int PutLine(char *line,  LineBuff *lb);
int GetLine(LineBuff *lb, char *line);
int Split(char *line, char ch,int maxw, char *word[], int len[]);
int ReadLine(const int fd, FileBuff *fb, char *line, int llen);
int SuperReadLine(const int fd, FileBuff *fb, char *line, int llen, int *flds);
int WriteLine(const int fd, FileBuff *fb, const char *src, const int length);
int ReadN(const int fd, FileBuff *fb, char *block, int size);
int WriteN(const int fd, const char *vptr, const int n);
int WriteN_wld(const int fd, const char *vptr, const int n);
void Char2BCD(char *src, char *dest, int cnum);
void BCD2Char(char *src, char *dest, int cnum);
int isSame(char *src, char *dest, int len);
void *Malloc(unsigned capacity);
int Atoi(char *src);
int ReadConfig(char *filename, Config *cfg);
void PrintCfg(Config *cfg);
void ExecCmd(const char *cmd);
int System( char *cmd);
time_t ToTime_t(char *src);
char *Now(char *now);
static void ShowTimes(void);
void ReadDir(int begin);
char *CurDir(char *dirname);
int Open(char *path, int oflag);
int Remove(char *path);
int Stat(char *path, struct stat *buf);
int PthreadCreate(pthread_t *tid, const pthread_attr_t *attr, void *(start_routine (void *)),void *arg);
pid_t Fork(void);
void SigChld(int sig);
int DaemonInit(void);
void PrintEnv(void);

// 取得系统当前时间
// str_sys_time 返回"1970-01-01 08:00:00"格式字符串
// 函数返回值为秒数
time_t get_system_time(char *str_curr_system_time);

// 取得系统当前时间
// str_sys_time 返回"19710203040506"格式字符串
// 函数返回值为秒数
time_t get_system_time_2(char *str_curr_system_time);

// 根据输入时间，转换为YYYYMMDDHHMMSS格式
// str_time 返回"20100315100000"格式字符串
// 函数返回值为tm
tm * get_str_time(char *str_time,time_t t);

// 根据输入时间，对分钟和秒钟部分清零
// 获取小时级的时间戳
// str_time 返回"20100315100000"格式字符串
// 函数返回值为time_t
time_t get_hour_time(time_t t);

int GetStr(char* , char* , int, char);

void LTrim(char* , char );

void RTrim(char* , char );


int Split_decode(char *line, char ch,int maxw, char *word[], int len[]);

int write_heart_file(char *filename);
int write_error_file(char *filepath,char *modulename,char *errcode,int level,char *errinfo);
int write_log_file(char *filepath,char *modulename,char *msgcode,char *file_name,char *end_time,char *msgvalue);
#endif
