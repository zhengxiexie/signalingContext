#ifndef _SSCONTEXT_H
#define _SSCONTEXT_H

/*
#include "ssnet.h"
*/

typedef struct {
	//char msisdn[12];
	char msisdn[16];
	char imsi[16];
	char last_cell[11];
	char mobile_status;					// 当前手机状态 0-状态不详 1-关机 2-开机 3-即开机也关机
	/*
	unsigned int smo_sms_counts;		// 发送短信次数
	unsigned int calling_call_counts;	// 打电话次数
	unsigned int calling_call_duration;	// 打电话总时间
	unsigned int smt_sms_counts;		// 接受短信次数
	unsigned int called_call_counts;	// 接电话次数
	unsigned int called_call_duration;	// 接电话总时间
	*/
	unsigned short int smo_sms_counts;			// 发送短信次数
	unsigned short int calling_call_counts;		// 打电话次数
	unsigned short int calling_call_duration;	// 打电话总时间
	unsigned short int smt_sms_counts;			// 接受短信次数
	unsigned short int called_call_counts;		// 接电话次数
	unsigned short int called_call_duration;	// 接电话总时间
	unsigned short int mo_mms_counts;			  // 发送彩信次数
	unsigned short int mt_mms_counts;			  // 接受彩信次数	
	time_t	come_time;							// 进入小区时间
	time_t	leave_time;							// 离开小区时间
	time_t	ler_time;							  // 信令事件时间
	unsigned short int resident_time;	   		// 当前驻留时长,单位:分钟

	char other_numbers[MAX_OTHER_NUMBERS_LEN];	// 对段号码信息（包括打电话、接电话、发短信、接短信行为的对段号码）

	char calling_other_party_area[MAX_AREA_LEN];	// 对段号码归属地信息(打电话)
	char called_other_party_area[MAX_AREA_LEN];		// 对段号码归属地信息(接电话)

	char last_action_type[MAX_LAST_ACTION_TYPE_LEN];		// 最后一次更新事件类型
	char cause[MAX_CAUSE_LEN];							          // 事件原因码	
	
	char local_prov_flag[MAX_LOCAL_PROV_FLAG_LEN];			  // 是否本省用户 1本省用户 0非本省用户
	char prov_code[MAX_PROV_CODE_LEN];	// 本省编码	
	char city_code[MAX_CITY_CODE_LEN];	// 地市编码
		
} Context;

typedef struct { 
	//因考虑到给国外用户做营销，msisdn为可变，去掉压缩
	//char msisdn[6];		
	
	char msisdn[16];		
	char local_prov_flag[MAX_LOCAL_PROV_FLAG_LEN];			  // 是否本省用户 1本省用户 0非本省用户
	char prov_code[MAX_PROV_CODE_LEN];	// 本省编码	
	char city_code[MAX_CITY_CODE_LEN];	// 地市编码
	
/*	char last_cell[11];							          // 说明：由于含有字符，无法进行压缩
	char mobile_status;							          // 当前手机状态 0-状态不详 1-关机 2-开机 3-即开机也关机
	unsigned short int smo_sms_counts;			  // 发送短信次数
	unsigned short int calling_call_counts;		// 打电话次数
	unsigned short int calling_call_duration;	// 打电话总时间
	unsigned short int smt_sms_counts;			  // 接受短信次数
	unsigned short int called_call_counts;		// 接电话次数
	unsigned short int called_call_duration;	// 接电话总时间
	time_t	come_time;							// 进入小区时间
	time_t	leave_time;							// 离开小区时间
	time_t	ler_time;							  // 信令事件时间
	unsigned short int resident_time;			// 当前驻留时长,单位:分钟

	char other_numbers[MAX_OTHER_NUMBERS_LEN];	// 对段号码信息（包括打电话、接电话、发短信、接短信、发彩信、接彩信行为的对段号码）

	char calling_other_party_area[MAX_AREA_LEN];	// 对段号码归属地信息(打电话)
	char called_other_party_area[MAX_AREA_LEN];		// 对段号码归属地信息(接电话)

	char last_action_type[MAX_LAST_ACTION_TYPE_LEN];		// 最后一次更新事件类型
*/
} BCDContext;

typedef struct {
	char imsi[6];		
	//unsigned int offset;
	//unsigned int redirect;
	int offset;
	int redirect;
} BCDIndex;


//===============================================
/*
struct InfoStat
{
	string other_numbers;
	
    InfoStat()
    {

    }
};
*/

//extern map<string, InfoStat> m_Number_Info;

//==============================================

/*
extern char		**m_physical_area;
extern int		physical_area_num;
*/
extern int		exitflag;
extern int		file_read_exitflag;

extern Check chk;
//extern Config *cfg;
extern Analyze ana;

extern BCDContext *context;
extern BCDIndex	 *Index;
extern BCDIndex	*redirect;

extern pthread_mutex_t		filtrate_mutex;
extern pthread_mutex_t		pthread_init_mutex;
extern pthread_mutex_t		pthread_logfile_mutex;

extern int WriteResult(int ruleid, char *src);

void *init_timer(void *arg);
void *backup_timer(void *arg);
void *log_timer(void *arg);
int InitContext(void);
int InitLocalContext(void);
int InsertContext(char *imsi,char *msisdn);
int RestoreContext(char *fromfile);
int BackupContext(char *tofile);
int WriteContextBuf(int i, int fd, char *imsi, FileBuff *lb);
int GetFromContext(char *imsi, Context *rec);
int PutToContext(char *imsi, Context *rec);
int FindIMSI(char *imsi);

void *load_timer(void *arg);

void PrintContext(Context *rec);
int update_user_resident_time();

int read_conflict_file(char *map_file_name);
int read_context_file(char *map_file_name);

int export_file(void);

#endif
