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
	char mobile_status;					// ��ǰ�ֻ�״̬ 0-״̬���� 1-�ػ� 2-���� 3-������Ҳ�ػ�
	/*
	unsigned int smo_sms_counts;		// ���Ͷ��Ŵ���
	unsigned int calling_call_counts;	// ��绰����
	unsigned int calling_call_duration;	// ��绰��ʱ��
	unsigned int smt_sms_counts;		// ���ܶ��Ŵ���
	unsigned int called_call_counts;	// �ӵ绰����
	unsigned int called_call_duration;	// �ӵ绰��ʱ��
	*/
	unsigned short int smo_sms_counts;			// ���Ͷ��Ŵ���
	unsigned short int calling_call_counts;		// ��绰����
	unsigned short int calling_call_duration;	// ��绰��ʱ��
	unsigned short int smt_sms_counts;			// ���ܶ��Ŵ���
	unsigned short int called_call_counts;		// �ӵ绰����
	unsigned short int called_call_duration;	// �ӵ绰��ʱ��
	unsigned short int mo_mms_counts;			  // ���Ͳ��Ŵ���
	unsigned short int mt_mms_counts;			  // ���ܲ��Ŵ���	
	time_t	come_time;							// ����С��ʱ��
	time_t	leave_time;							// �뿪С��ʱ��
	time_t	ler_time;							  // �����¼�ʱ��
	unsigned short int resident_time;	   		// ��ǰפ��ʱ��,��λ:����

	char other_numbers[MAX_OTHER_NUMBERS_LEN];	// �Զκ�����Ϣ��������绰���ӵ绰�������š��Ӷ�����Ϊ�ĶԶκ��룩

	char calling_other_party_area[MAX_AREA_LEN];	// �Զκ����������Ϣ(��绰)
	char called_other_party_area[MAX_AREA_LEN];		// �Զκ����������Ϣ(�ӵ绰)

	char last_action_type[MAX_LAST_ACTION_TYPE_LEN];		// ���һ�θ����¼�����
	char cause[MAX_CAUSE_LEN];							          // �¼�ԭ����	
	
	char local_prov_flag[MAX_LOCAL_PROV_FLAG_LEN];			  // �Ƿ�ʡ�û� 1��ʡ�û� 0�Ǳ�ʡ�û�
	char prov_code[MAX_PROV_CODE_LEN];	// ��ʡ����	
	char city_code[MAX_CITY_CODE_LEN];	// ���б���
		
} Context;

typedef struct { 
	//���ǵ��������û���Ӫ����msisdnΪ�ɱ䣬ȥ��ѹ��
	//char msisdn[6];		
	
	char msisdn[16];		
	char local_prov_flag[MAX_LOCAL_PROV_FLAG_LEN];			  // �Ƿ�ʡ�û� 1��ʡ�û� 0�Ǳ�ʡ�û�
	char prov_code[MAX_PROV_CODE_LEN];	// ��ʡ����	
	char city_code[MAX_CITY_CODE_LEN];	// ���б���
	
/*	char last_cell[11];							          // ˵�������ں����ַ����޷�����ѹ��
	char mobile_status;							          // ��ǰ�ֻ�״̬ 0-״̬���� 1-�ػ� 2-���� 3-������Ҳ�ػ�
	unsigned short int smo_sms_counts;			  // ���Ͷ��Ŵ���
	unsigned short int calling_call_counts;		// ��绰����
	unsigned short int calling_call_duration;	// ��绰��ʱ��
	unsigned short int smt_sms_counts;			  // ���ܶ��Ŵ���
	unsigned short int called_call_counts;		// �ӵ绰����
	unsigned short int called_call_duration;	// �ӵ绰��ʱ��
	time_t	come_time;							// ����С��ʱ��
	time_t	leave_time;							// �뿪С��ʱ��
	time_t	ler_time;							  // �����¼�ʱ��
	unsigned short int resident_time;			// ��ǰפ��ʱ��,��λ:����

	char other_numbers[MAX_OTHER_NUMBERS_LEN];	// �Զκ�����Ϣ��������绰���ӵ绰�������š��Ӷ��š������š��Ӳ�����Ϊ�ĶԶκ��룩

	char calling_other_party_area[MAX_AREA_LEN];	// �Զκ����������Ϣ(��绰)
	char called_other_party_area[MAX_AREA_LEN];		// �Զκ����������Ϣ(�ӵ绰)

	char last_action_type[MAX_LAST_ACTION_TYPE_LEN];		// ���һ�θ����¼�����
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
