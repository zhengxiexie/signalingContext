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

//���ô����ݿ��ж�ȡ���ݵ���󻺳�����
#define		MAX_EXTRACT_ROW	10000

//���������ֻ�����ǰ׺�� 
#define		MAX_MOBILE_PREFIX_NUM	50

//������BCDContext�жԶκ�������洢���ȣ��������˳���ʱ���������ĵ���Ϣ�����
//����ܳ���100�ֽ�!!!!!!!!! ��Ϊload�еı�����ֶξ�������100���ֽ�
//�������25���ֽڵ�����
//��֤�ڴ�ĵ����ʹ�������Դ�ֵ�ĵ�������Ӱ���ʼ��ʱ������ڴ��С
//#define		MAX_OTHER_NUMBERS_LEN	30	// ûɶ�������Ҫ���׶�
#define		MAX_OTHER_NUMBERS_LEN	50	// ûɶ�������Ҫ���׶�


//����ܳ���30�ֽ�!!!!!!!!! ��Ϊload�еı�����ֶξ�������30���ֽ�
#define		MAX_AREA_LEN	10	// ûɶ�������Ҫ���׶�

#define		MAX_AREA_LEN	10	// ûɶ�������Ҫ���׶�

#define		MAX_LAST_ACTION_TYPE_LEN	11	// ûɶ�������Ҫ���׶�
#define		MAX_CAUSE_LEN	5	// ûɶ�������Ҫ���׶�

#define		MAX_PROV_CODE_LEN	5	// ûɶ�������Ҫ���׶�
#define		MAX_CITY_CODE_LEN	6	// ûɶ�������Ҫ���׶�
#define		MAX_LOCAL_PROV_FLAG_LEN	2	// ûɶ�������Ҫ���׶�

// ����ʼ��ʱ��������Ҫ���ص��û���������Ϣ
// Ŀǰ�����ÿ�γ�ʼ��ʱ����������ǰ�û���Ϣ
#define		RESTORE_FILE_NAME "../data/context.txt"

#define		MAX_LOAD_FILE_NUM 10

#define		BACKUP_FILE_PREFIX "../output/out_bak/backup_context"

// ����ʡ�ݣ������ֲ�ͬʡ�нӿڲ�ͬ
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

	//����ͣ��ʱ��ķ�ֵ
	unsigned int resident_time_raft;
	unsigned int resident_time_interval;

	//������������ļ�·�����ļ���ǰ׺����
	char load_file_prefix[201];
	char output_file_suffix[50];	
		
	//# ������Socket��ʽʱ�����ö�ȡ����ֹͣ�ڼ�����������ļ���·��
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

// ȡ��ϵͳ��ǰʱ��
// str_sys_time ����"1970-01-01 08:00:00"��ʽ�ַ���
// ��������ֵΪ����
time_t get_system_time(char *str_curr_system_time);

// ȡ��ϵͳ��ǰʱ��
// str_sys_time ����"19710203040506"��ʽ�ַ���
// ��������ֵΪ����
time_t get_system_time_2(char *str_curr_system_time);

// ��������ʱ�䣬ת��ΪYYYYMMDDHHMMSS��ʽ
// str_time ����"20100315100000"��ʽ�ַ���
// ��������ֵΪtm
tm * get_str_time(char *str_time,time_t t);

// ��������ʱ�䣬�Է��Ӻ����Ӳ�������
// ��ȡСʱ����ʱ���
// str_time ����"20100315100000"��ʽ�ַ���
// ��������ֵΪtime_t
time_t get_hour_time(time_t t);

int GetStr(char* , char* , int, char);

void LTrim(char* , char );

void RTrim(char* , char );


int Split_decode(char *line, char ch,int maxw, char *word[], int len[]);

int write_heart_file(char *filename);
int write_error_file(char *filepath,char *modulename,char *errcode,int level,char *errinfo);
int write_log_file(char *filepath,char *modulename,char *msgcode,char *file_name,char *end_time,char *msgvalue);
#endif
