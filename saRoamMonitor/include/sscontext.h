#ifndef _SSCONTEXT_H
#define _SSCONTEXT_H

#include "ssnet.h"

typedef struct {
	char msisdn[16];
	char imsi[16];
	time_t	come_time;							//����ʱ��
	time_t	leave_time;							//�뿪ʱ��
	char str_come_time[27];         //����ʱ�� --΢��
	char str_leave_time[27];        //�뿪ʱ�� --΢��
	unsigned int resident_time;	   	//��ǰפ��ʱ��,��λ:��
	char hlr[16];
	char vlr[16];
	int user_type;                        // 0-������״̬��1-����״̬
	char current_vlr[16];                 // ��ǰVLR
	time_t current_delete_time;           // ��ǰVLRɾ��ʱ��
	char str_current_delete_time[27];     // ��ǰVLRɾ��ʱ�� ΢��
	time_t current_update_time;           // ��ǰVLR����ʱ��
	char str_current_update_time[27];     // ��ǰVLR����ʱ�� ΢��
	char latest_vlr[16] ;                   // ���VLR            
	time_t latest_update_time;            // �������ʱ��
	char str_latest_update_time[27];       // ���VLR����ʱ�� ΢��
	time_t latest_delete_time;            // ���ɾ��ʱ��
	char str_latest_delete_time[27];     // ���VLRɾ��ʱ�� ΢��
} Context;

typedef struct { 
	char msisdn[16];		
	time_t	come_time;							 //����ʱ��
	time_t	leave_time;							//�뿪ʱ��
	char str_come_time[27];           //����ʱ�� --΢��
	char str_leave_time[27];          //�뿪ʱ�� --΢��
	unsigned int resident_time;	   	 //��ǰפ��ʱ��,��λ:��
	char hlr[16];
	char vlr[16];
	int user_type;                 // 0-������״̬��1-����״̬
	char current_vlr[16];                 // ��ǰVLR
	time_t current_delete_time;           // ��ǰVLRɾ��ʱ��
	char str_current_delete_time[27];     // ��ǰVLRɾ��ʱ�� ΢��
	time_t current_update_time;           // ��ǰVLR����ʱ��
	char str_current_update_time[27];     // ��ǰVLR����ʱ�� ΢��
	char latest_vlr[16] ;                   // ���VLR            
	time_t latest_update_time;            // �������ʱ��
	char str_latest_update_time[27];       // ���VLR����ʱ�� ΢��
	time_t latest_delete_time;            // ���ɾ��ʱ��
	char str_latest_delete_time[27];     // ���VLRɾ��ʱ�� ΢��
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
