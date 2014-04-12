#ifndef _SSCONTEXT_H
#define _SSCONTEXT_H

#include "ssnet.h"

typedef struct {
	char msisdn[16];
	char imsi[16];
	time_t	come_time;							//进入时间
	time_t	leave_time;							//离开时间
	char str_come_time[27];         //进入时间 --微秒
	char str_leave_time[27];        //离开时间 --微秒
	unsigned int resident_time;	   	//当前驻留时长,单位:秒
	char hlr[16];
	char vlr[16];
	int user_type;                        // 0-非漫游状态，1-漫游状态
	char current_vlr[16];                 // 当前VLR
	time_t current_delete_time;           // 当前VLR删除时间
	char str_current_delete_time[27];     // 当前VLR删除时间 微妙
	time_t current_update_time;           // 当前VLR更新时间
	char str_current_update_time[27];     // 当前VLR更新时间 微妙
	char latest_vlr[16] ;                   // 最近VLR            
	time_t latest_update_time;            // 最近更新时间
	char str_latest_update_time[27];       // 最近VLR更新时间 微妙
	time_t latest_delete_time;            // 最近删除时间
	char str_latest_delete_time[27];     // 最近VLR删除时间 微妙
} Context;

typedef struct { 
	char msisdn[16];		
	time_t	come_time;							 //进入时间
	time_t	leave_time;							//离开时间
	char str_come_time[27];           //进入时间 --微秒
	char str_leave_time[27];          //离开时间 --微秒
	unsigned int resident_time;	   	 //当前驻留时长,单位:秒
	char hlr[16];
	char vlr[16];
	int user_type;                 // 0-非漫游状态，1-漫游状态
	char current_vlr[16];                 // 当前VLR
	time_t current_delete_time;           // 当前VLR删除时间
	char str_current_delete_time[27];     // 当前VLR删除时间 微妙
	time_t current_update_time;           // 当前VLR更新时间
	char str_current_update_time[27];     // 当前VLR更新时间 微妙
	char latest_vlr[16] ;                   // 最近VLR            
	time_t latest_update_time;            // 最近更新时间
	char str_latest_update_time[27];       // 最近VLR更新时间 微妙
	time_t latest_delete_time;            // 最近删除时间
	char str_latest_delete_time[27];     // 最近VLR删除时间 微妙
} BCDContext;

typedef struct {
	//char imsi[6];
	char imsi[MAX_BCD_IMSI_LEN];
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




extern Check chk;
extern BCDContext *context;
extern BCDIndex	 *Index;
extern BCDIndex	*redirect;

void *init_timer(void *arg);
void init_timer(int event_hour);
void *backup_timer(void *arg);
int InitContext(char *filename);
int InsertContext(char *imsi,char *msisdn);
int RestoreContext(char *fromfile);
int BackupContext(char *tofile);
int WriteContextBuf(int i, int fd, char *imsi, FileBuff *lb);
int GetFromContext(char *imsi, Context *rec);
int PutToContext(char *imsi, Context *rec);
int FindIMSI(char *imsi);
int ResetIndex(char *imsi);
//void *load_timer(void *arg);
int load_timer();
void *resident_timer(void *arg);

void PrintContext(Context *rec);

int update_user_resident_time();

#endif
