#include <time.h>

#include "sspublic.h"
#include "ssnet.h"
#include "sscontext.h"
#include "ssanalyze.h"
#ifdef _ORACLE_
#include "ssoracle.h"
#endif /* _ORACLE */
#ifdef _DB2_
#include "ssdb2.h"
#endif /* _DB2_ */




// ���ӳ�ʼ��������
pthread_mutex_t pthread_init_mutex;

// �������������
int field_imsi_num = 0;
int field_msisdn_num = 0;
int field_event_type_num = 0;
int field_time_stamp_num = 0;
int field_duration_num = 0;
int field_lac_id_num = 0;
int field_ci_id_num = 0;
int field_cause_num = 0;
int field_other_party_num = 0;

int field_local_prov_flag_num = 0;
int field_prov_code_num = 0;
int field_city_code_num = 0;


char							**m_event_type;
int								event_type_num;

char							**m_physical_area;
int								physical_area_num;	

// ���ӹ��˻�����
pthread_mutex_t filtrate_mutex;

// ��־������
pthread_mutex_t pthread_logfile_mutex;

//set<string> 				m_access_number;
//set<string>::iterator 		m_pos_access_number;

string access_numbers;


bool operator==(const decode_map& w1, const decode_map& w2)
{
    	if(strcmp(w1.field_name, w2.field_name) < 0)
      	{
			return true;
      	}

		return false;
}

bool operator<(const decode_map& w1, const decode_map& w2)
{
    	if(strcmp(w1.field_name, w2.field_name) < 0)
      	{
			return true;
      	}

		return false;
}


void *consume( void *arg)
{
	int i,ret,ruleid;

	int len[50];
	char *word[50];

	char imsi[16];
	Context rec;		
	char line[BIG_MAXLINE], line_tmp[BIG_MAXLINE];
	char str_result[BIG_MAXLINE];

	char msisdn[30];	// ���˺���
	char tmp_msisdn[30]; //��ʱ�洢���룬�Դ���ps�ӿ�ʹ�����С�����ʱҪ���ֱ�������
	char errinfo[200];	
	
	char str_tmp[2];
	time_t event_time;
	
	char event_type[10];	
	char str_user_event_type[10];
	char lac_id[10], str_lac_id[10];
	char ci_id[10], str_ci_id[10];
	char lac_ci_id[20];
	char str_event_time[20];	
	
	char local_prov_flag[MAX_LOCAL_PROV_FLAG_LEN] ;			  // �Ƿ�ʡ�û� 1��ʡ�û� 0�Ǳ�ʡ�û�
	char prov_code[MAX_PROV_CODE_LEN];	// ��ʡ����	
	char city_code[MAX_CITY_CODE_LEN];	// ���б���
			
	struct tm *tp;
	
	int pthread_id;
	
	pthread_id = pthread_self();
	
	memset(&rec, '\0', sizeof(rec));	
    
	printf("�����߳�[%d]����...\n", pthread_id);

	while(1)
	{
		pthread_mutex_lock(&lb.mutex);
		while( lb.lines <= 0 && exitflag==0 )
		{	
			pthread_cond_wait(&lb.more, &lb.mutex);
		}

    //������������ϲ����˳�
    //if((lb.lines <= 0) && (exitflag>0) && (file_read_exitflag > 0))
		if((lb.lines <= 0) && (exitflag != 0))
		{
			//�����˳�ʱ����Ҫ�������������������������ļ�������,
			//�ٰѻ�����д���ļ����ر��ļ�
		  //���������򲻻ᶪλ�����ݣ���֤��������
		  //�����˳��൱������ʼ��   20100409
			//��������Ϣ���������
			//ʵʱӪ������Ҫ�������������������������ļ�������
		 	//ret = update_user_resident_time_exit(); 
		 				
			for(i=0; i<chk.load_file_num; i++){
					pthread_mutex_lock( &ana.mutex[i]);
				  if( ana.counts[i] > 0 ) {
						if(ana.fd[i]<=0){
							ana.fd[i] = open(ana.fname[i], O_APPEND|O_WRONLY|O_CREAT, 0644);
						}
						WriteN(ana.fd[i],ana.fbuf+i*FBUFFSIZE, ana.num[i]);
						close(ana.fd[i]);
     			}					
					pthread_mutex_unlock( &ana.mutex[i] );			
			}
			exitflag++;
			pthread_cond_broadcast(&lb.more);
			pthread_mutex_unlock(&lb.mutex);
			memset(errinfo,'\0',sizeof(errinfo));
			sprintf(errinfo,"�����Ĵ����߳��˳�,������飡");		   
			printf("%s\n",errinfo);
			write_error_file(chk.err_file_path,"smLocalContext","64",2,errinfo);				
			pthread_exit(0);
		}

		memset(line_tmp, '\0', sizeof(line_tmp));
		memset(line, '\0', sizeof(line));
		
		ret = GetLine(&lb, line);
		//printf("��ǰ������������Ϊ=[%s]\n", line);

		pthread_cond_signal(&lb.less);
		pthread_mutex_unlock(&lb.mutex);
    
		//������������
		strcpy(line_tmp, line);		
		ret=Split(line_tmp, ',', 50, word, len);
		
		//printf("line_tmp=[%s]\n", line_tmp);
		//printf("line=%s", line);

    //imsi���Ȳ�Ϊ15λ����Ϊ��������
		if(strlen(word[field_imsi_num]) != 15)
		{
		  memset(errinfo,'\0',sizeof(errinfo));
		  sprintf(errinfo,"imsi���Ȳ�Ϊ15λ��imsi=[%s] ���ע��", word[field_imsi_num]);	
		  //printf("imsi���Ȳ�Ϊ15λ ���ע line=%s", line);  
		  write_error_file(chk.err_file_path,"smLocalContext","7",2,errinfo);		
		  continue;
		}
				
		//ȡ��imsi
		memset(imsi, '\0', sizeof(imsi));
		strcpy(imsi, word[field_imsi_num]);
		LTrim(imsi, ' ');
		RTrim(imsi, ' ');
		//printf("imsi=[%s]\n", imsi);

		//ȡ���ֻ�������Ϣ��ʼ
		memset(msisdn, '\0', sizeof(msisdn));
		memset(tmp_msisdn, '\0', sizeof(tmp_msisdn));
		
		memset(event_type, '\0', sizeof(event_type));
		strcpy(event_type, word[field_event_type_num]);
		//printf("event_type=[%s]\n", event_type);
			
		/*	
		PS����뻥����Ԥ���������
		if(strcmp(event_type, "702") == 0 )		//PS�򱻽�ʱ ȡ���ж�Ϊ���˺���
		{
			strcpy(tmp_msisdn, word[field_other_party_num]);
		}
		else
		{
			strcpy(tmp_msisdn, word[field_msisdn_num]);
		}
		*/
		
		strcpy(tmp_msisdn, word[field_msisdn_num]);						
		LTrim(tmp_msisdn, ' ');
		RTrim(tmp_msisdn, ' ');		

		
		//ʹ�������к���ʱ��������ǰ׺Ϊ86ʱ���޳�ǰ׺86
		if(( 1 == chk.imsi_msisdn_flag ) && (strlen(tmp_msisdn)>2) && (strncmp(tmp_msisdn, "86", 2) == 0))
		{
  		for(i=2;i<(strlen(tmp_msisdn));i++) 
  		{
  			msisdn[i-2] = tmp_msisdn[i];
  		}			
		}
		else
		{
			strcpy(msisdn, tmp_msisdn);
		}

    //printf("msisdn=[%s]\n", msisdn);
    //ʹ�������к���ʱ�����޳�86����볤�Ȳ�Ϊ11λ�����޳�
		if(( 1 == chk.imsi_msisdn_flag ) && (strlen(msisdn)!=11) )
		{
       continue;	
		}
		
		//printf("msisdn1=[%s]\n", msisdn);

		memset(&rec, '\0', sizeof(rec));	
		memset(str_result, '\0', sizeof(str_result));

		//�������¼�ʱ���н�ȡ19λ
		memset(str_event_time, '\0', sizeof(str_event_time));
		strncpy(str_event_time, word[field_time_stamp_num], 19);
		//printf("word[field_time_stamp_num]=[%s]\n", word[field_time_stamp_num]);
		//printf("str_event_time=[%s]\n", str_event_time);	
		
		memset(lac_id, '\0', sizeof(lac_id));
		strcpy(lac_id, word[field_lac_id_num]);
		
		LTrim(lac_id, ' ');
		RTrim(lac_id, ' ');
		//add by chengxc
		//printf("%s size:%d\n",lac_id,strlen(lac_id));
		//�޸�lac��cellΪ���޳�������Ϊ��ͬʱ��Ϊ���γ�ʡ601ʱ�޳�
		
		memset(ci_id, '\0', sizeof(ci_id));
		strcpy(ci_id, word[field_ci_id_num]);
		
		LTrim(ci_id, ' ');
		RTrim(ci_id, ' ');
		//add by chengxc
		//printf("%s size:%d\n",ci_id,strlen(ci_id));

		memset(local_prov_flag, '\0', sizeof(local_prov_flag));
		strcpy(local_prov_flag, word[field_local_prov_flag_num]);

		memset(prov_code, '\0', sizeof(prov_code));
		strcpy(prov_code, word[field_prov_code_num]);
		
		memset(city_code, '\0', sizeof(city_code));
		strcpy(city_code, word[field_city_code_num]);
			  
		// =========================================================================
		// ====================== ��ع��˴������ =================================
		// =========================================================================

		memset(&rec, '\0', sizeof(rec));	
		memset(str_result, '\0', sizeof(str_result));

		//lac��cellΪ0��-1����ʾ����
		if ( (0 == strcmp(lac_id, "-1")) || (0 == strcmp(lac_id, "0"))  || (0 == strcmp(ci_id, "-1")) || (0 == strcmp(ci_id, "0"))  ){
			tp = localtime(&event_time);
			sprintf(str_event_time, "%4d-%02d-%02d %02d:%02d:%02d",
			tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	
		  memset(errinfo,'\0',sizeof(errinfo));
		  sprintf(errinfo,"lac��cell����imsi=[%s],event_time=[%s]���ע��", imsi,str_event_time);	
		  //printf("lac��cell�������ע line=%s", line);   
		  write_error_file(chk.err_file_path,"smLocalContext","66",2,errinfo);	
		  continue;					
		}
		
	  //����Ϊ����Ҫ��ʡ�û�ʱ��ֱ���޳���ʡ
		if ( (1 == chk.other_prov_flag) && (0 == strcmp(local_prov_flag, "0")) ){
		  continue;					
		}		
		
		pthread_mutex_lock(&chk.mutex);
			
		ret=GetFromContext(imsi, &rec);	
		if( -1 == ret ) {
			  
			  //ֱ���޳�����
			  //1:����Ϊ��
			  //2:ʡ�ݱ�ʶΪ��
			  //3:����Ϊ�޳���ʡ�û�������Ϊ��ʡ�û�
				if((strlen(msisdn) == 0) || (strlen(local_prov_flag) == 0) ) {
						//imsi����ӳ���ʱ�޳�����
						//1:����Ϊ�� 
						//2���벻Ϊ�գ���Ϊ��ʡ�û�(��Ϊδ֪ʡ���û�)
						//printf("-1 == ret imsi=%s\n",imsi);
						pthread_mutex_unlock(&chk.mutex);
						continue;
				}
								  
			  if((1 == chk.imsi_msisdn_flag)){
						//printf("before InsertContext,context_capacity=%d,context_capacity_used=%d\n",chk.context_capacity,chk.context_capacity_used);		 
				  	
				  	//Ԥ���������Ŀռ����꣬����imsi����̬����
						if(chk.context_capacity <= chk.context_capacity_used){
				  	   memset(errinfo,'\0',sizeof(errinfo));
			    	   sprintf(errinfo,"�û�[%s]���������ĵ�����������ÿͻ���Ϣ���������ע��", line);		   
			    	   write_error_file(chk.err_file_path,"smLocalContext","51",2,errinfo);								
							 pthread_mutex_unlock(&chk.mutex);
							 continue;							
						}
															
						InsertContext(imsi,msisdn);
          	
						strcpy(rec.local_prov_flag, local_prov_flag);						
						strcpy(rec.prov_code, prov_code);	
						strcpy(rec.city_code, city_code);	
													
						PutToContext(imsi, &rec);
						    
						//printf("after InsertContext,context_capacity=%d,context_capacity_used=%d\n",chk.context_capacity,chk.context_capacity_used);
						ret=GetFromContext(imsi, &rec);				  	
			  }else if( 0 == chk.imsi_msisdn_flag )  {
			  	
						if( (strcmp(local_prov_flag, "1") == 0) ) {
								//imsi����ӳ���ʱ�޳�����
								//1������Ϊ��
								//2�����벻Ϊ�գ���Ϊ��ʡ�û�(��Ϊδ֪ʡ���û�)
								//printf("-1 == ret imsi=%s\n",imsi);
								pthread_mutex_unlock(&chk.mutex);
								continue;						
						}

				  	//Ԥ���������Ŀռ����꣬����imsi����̬����
						if(chk.context_capacity <= chk.context_capacity_used){
				  	   memset(errinfo,'\0',sizeof(errinfo));
			    	   sprintf(errinfo,"�û�[%s]���������ĵ�����������ÿͻ���Ϣ���������ע��", line);		   
			    	   write_error_file(chk.err_file_path,"smLocalContext","51",2,errinfo);								
							 pthread_mutex_unlock(&chk.mutex);
							 continue;							
						}
						InsertContext(imsi,msisdn);
          	
						strcpy(rec.local_prov_flag, local_prov_flag);				
						strcpy(rec.prov_code, prov_code);	
						strcpy(rec.city_code, city_code);	
													
						PutToContext(imsi, &rec);
						
						//printf("after InsertContext,context_capacity=%d,context_capacity_used=%d\n",chk.context_capacity,chk.context_capacity_used);
						ret=GetFromContext(imsi, &rec);	
			  } else {
			  		printf("����imsi_msisdn_flagѡ�����\n");
						pthread_mutex_unlock(&chk.mutex);
						continue;			  	
			  }
		} 
		
		ret = update_user_info(word, &rec, str_result);
		//testGet(imsi);
		
		pthread_mutex_unlock(&chk.mutex);
		
		// ��ӡ������IMSI���������ж�Ӧ����Ϣ
		//PrintContext(&rec);   
	}
}


int update_user_info(char *word[], Context *rec, char *str_result_tmp)
{
	char imsi[16];
	char event_type[10];
	time_t event_time;
	char str_event_time[20];
	int duration;
	char lac_id[10], str_lac_id[10];
	char ci_id[10], str_ci_id[10];
	char cause[10];

	char msisdn[30];	// ���˺���
	char opp_num[MAX_OTHER_NUMBERS_LEN];	// �Զ˺���

	// ��ʼ����ֵ����ָֹ��Ϊ��
	char* msisdn_cleanout = "1111";		// ���˺���
	char* opp_num_cleanout = "2222";	// �Զ˺���

	char lac_ci_id[20];

	time_t curr_system_time;
	char str_curr_system_time[20];

	struct tm *tp;
	
	int ret=0;//������lac-cell����������lac-cell��ͬʱΪ1 ����Ϊ0 Ϊ1��ʾҪ������������lac-cell
  int ruleid;

	char str_tmp[2];
	
	int lac_ci_flag = 0;

	// =======================================================
	// ============= ȡ���ֻ�������Ϣ��ʼ ====================
	// =======================================================
	memset(msisdn, '\0', sizeof(msisdn));
	
	//�����Ǵ�imsi��msisdnӳ���ȡ���룬���Ǵ���������ȡ���룬���ȱ��棬��ʹ�ã�
	//������ͬһimsi����������ʱû�ṩ����Ҳ���������
	strcpy(msisdn, rec->msisdn);
	//printf("in update_user_info msisdn=[%s]\n", msisdn);
	// =======================================================
	// ============= ȡ���ֻ�������Ϣ���� ====================
	// =======================================================

	// =======================================================
	// =========== ȡ�������и��ֶ����ݿ�ʼ ==================
	// =======================================================
	memset(imsi, '\0', sizeof(imsi));
	strcpy(imsi, word[field_imsi_num]);
	LTrim(imsi, ' ');
	RTrim(imsi, ' ');
	//printf("imsi=[%s]\n", imsi);

	memset(event_type, '\0', sizeof(event_type));
	strcpy(event_type, word[field_event_type_num]);
	//printf("event_type=[%s]\n", event_type);
	
	event_time = ToTime_t(word[field_time_stamp_num]);
	memset(str_event_time, '\0', sizeof(str_event_time));
	tp = localtime(&event_time);
	sprintf(str_event_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_event_time=[%s]\n", str_event_time);

	duration = atoi(word[field_duration_num]);
	//printf("duration=[%d]\n", duration);

	memset(lac_id, '\0', sizeof(lac_id));
	memset(str_lac_id, '\0', sizeof(str_lac_id));
	strcpy(lac_id, word[field_lac_id_num]);
	LTrim(lac_id, ' ');
	RTrim(lac_id, ' ');
	sprintf(str_lac_id, "%s", lac_id);
	//printf("lac_id=[%s]\n", lac_id);

	memset(ci_id, '\0', sizeof(ci_id));
	memset(str_ci_id, '\0', sizeof(str_ci_id));
	strcpy(ci_id, word[field_ci_id_num]);
	LTrim(ci_id, ' ');
	RTrim(ci_id, ' ');
	sprintf(str_ci_id, "%s", ci_id);
	//printf("ci_id=[%s]\n", ci_id);

	memset(lac_ci_id, '\0', sizeof(lac_ci_id));
	strcpy(lac_ci_id, str_lac_id);
	strcat(lac_ci_id, "-");
	strcat(lac_ci_id, str_ci_id);
	
	//�¼�ԭ�����ֶ��е�ʡ�п���û�У�������Ϊ��
	memset(cause, '\0', sizeof(cause));
  if(field_cause_num >= 0)
  {
		strcpy(cause, word[field_cause_num]);
	}
	//printf("cause=[%s]\n", cause);

	memset(opp_num, '\0', sizeof(opp_num));
	
	/*
	PS����뻥����Ԥ���������
	if(strcmp(event_type, "702") == 0 )		//PS�򱻽�ʱ ȡ���ж�Ϊ�Զ˺���
	{
		strcpy(opp_num, word[field_msisdn_num]);
	}
	else
	{
		strcpy(opp_num, word[field_other_party_num]);
	}	
	*/
	strcpy(opp_num, word[field_other_party_num]);		

	LTrim(opp_num, ' ');
	RTrim(opp_num, ' ');
	
	//printf("opp_num=[%s]\n", opp_num);
	// =======================================================
	// =========== ȡ�������и��ֶ����ݽ��� ==================
	// =======================================================


	// ȡ��ϵͳ��ǰʱ��
	memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
	time(&curr_system_time);
	tp = localtime(&curr_system_time);
	sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_curr_system_time=[%s]\n", str_curr_system_time);


	//printf("rec->last_cell=[%s]\n", rec->last_cell);
	// -------------------------------------------------------
	// -------------- �޸���������Ϣ��ʼ ---------------------
	// -------------------------------------------------------
	
	memset(str_tmp, '\0', sizeof(str_tmp));
	//strncpy(str_tmp, imsi+14, 1);

	//strncpy(str_tmp, (rec->msisdn)+10, 1);
	strncpy(str_tmp, msisdn+10, 1);
	
	//printf("str_tmp=[%s]\n", str_tmp);
	//ruleid = (atoi(str_tmp))%7;
	//ruleid = (atoi(str_tmp))%LOAD_FILE_NUM;
	ruleid = (atoi(str_tmp))%chk.load_file_num;
	//printf("aaaa str_tmp=[%s] ruleid=[%d]\n", str_tmp, ruleid);
			
	//���������¼�ʱ��
	rec->ler_time = event_time;
	
	strcpy(rec->cause, cause);
	
	memset(rec->last_cell, '\0', sizeof(rec->last_cell));
	strcpy(rec->last_cell, lac_ci_id);
	
	// ����ͳ����Ϣ
	rec->smo_sms_counts = 0;
	rec->calling_call_counts = 0;
	rec->calling_call_duration = 0;
	rec->mobile_status = '0';
	rec->smt_sms_counts = 0;
	rec->called_call_counts = 0;
	rec->called_call_duration = 0;
	rec->mo_mms_counts = 0;
	rec->mt_mms_counts = 0;
	
	// ���½���С��ʱ�䡢�뿪С��ʱ�䡢פ��ʱ��
	rec->leave_time = 0;
	rec->resident_time = 0;

	// ��ʼ���Զκ��벿��
	memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));

	// ��ʼ���Զκ����������Ϣ(��绰)
	memset(rec->calling_other_party_area, '\0', sizeof(rec->calling_other_party_area));

	// ��ʼ���Զκ����������Ϣ(�ӵ绰)
	memset(rec->called_other_party_area, '\0', sizeof(rec->called_other_party_area));

	if(strcmp(event_type, "101") == 0)		// ��绰
	{
		rec->calling_call_counts++;
		rec->calling_call_duration += duration;
  
		// ���Զ˺�����ֵʱ ���¶Զ˺���
		if(strlen(opp_num) > 0)
		{
			/*
			// ������ϴ
			msisdn_cleanout = numbers_cleanout(msisdn);
			opp_num_cleanout = numbers_cleanout(opp_num);
			//printf("msisdn=[%s] msisdn_cleanout=[%s] opp_num=[%s] opp_num_cleanout=[%s]\n", msisdn, msisdn_cleanout, opp_num, opp_num_cleanout);
  
			ret = update_user_other_numbers(event_type, opp_num, opp_num_cleanout, rec, str_result_tmp);
			*/
	
			memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "A");
			strcat(rec->other_numbers, opp_num);
			//printf("001\n");
			
			//strcpy(msisdn_cleanout, msisdn);
			//printf("002\n");
			
			// ������ϴ
			//opp_num_cleanout = numbers_cleanout(opp_num);
			// action_type: 1-��绰 ������ ������ 2-�ӵ绰 �Ӷ��� �Ӳ���
			//update_other_party_area(1, msisdn_cleanout, opp_num_cleanout, rec);
		}
	}
	else if(strcmp(event_type, "102") == 0)	// �ӵ绰
	{
		rec->called_call_counts++;
		rec->called_call_duration += duration;
  
		// ���Զ˺�����ֵʱ
		if(strlen(opp_num) > 0)
		{
			memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "B");
			strcat(rec->other_numbers, opp_num);
			
			// ������ϴ
			//opp_num_cleanout = numbers_cleanout(opp_num);
			// action_type: 1-��绰 ������ ������ 2-�ӵ绰 �Ӷ��� �Ӳ���
			//update_other_party_area(2, msisdn_cleanout, opp_num_cleanout, rec);
		}
	}
	else if(strcmp(event_type, "201") == 0)	// ������
	{
		rec->smo_sms_counts++;
  
		// ���Զ˺�����ֵʱ
		if(strlen(opp_num) > 0)
		{
		  memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "C");
			strcat(rec->other_numbers, opp_num);
			
			// ������ϴ
			//opp_num_cleanout = numbers_cleanout(opp_num);
			// action_type: 1-��绰 ������ ������ 2-�ӵ绰 �Ӷ��� �Ӳ���
			//update_other_party_area(1, msisdn_cleanout, opp_num_cleanout, rec);
		}
	}
	else if(strcmp(event_type, "202") == 0)	// �Ӷ���
	{
		rec->smt_sms_counts++;
  
		// ���Զ˺�����ֵʱ
		if(strlen(opp_num) > 0)
		{
			memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "D");
			strcat(rec->other_numbers, opp_num);

			// ������ϴ
			//opp_num_cleanout = numbers_cleanout(opp_num);
			// action_type: 1-��绰 ������ ������ 2-�ӵ绰 �Ӷ��� �Ӳ���
			//update_other_party_area(2, msisdn_cleanout, opp_num_cleanout, rec);				
		}
	}
	else if(strcmp(event_type, "701") == 0)	// ������
	{
		rec->mo_mms_counts++;
  
		// ���Զ˺�����ֵʱ
		if(strlen(opp_num) > 0)
		{
		  memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "E");
			strcat(rec->other_numbers, opp_num);
			
			// ������ϴ
			//opp_num_cleanout = numbers_cleanout(opp_num);
			//printf("opp_num=[%s] opp_num_cleanout=[%s]\n", opp_num,opp_num_cleanout);
			// action_type: 1-��绰 ������ ������ 2-�ӵ绰 �Ӷ��� �Ӳ���
			//update_other_party_area(1, msisdn_cleanout, opp_num_cleanout, rec);
			//printf("opp_num=[%s] opp_num_cleanout=[%s] rec->other_numbers=[%s] \n", opp_num,opp_num_cleanout,rec->other_numbers);	
		}
	}
	else if(strcmp(event_type, "702") == 0)	// �Ӳ���
	{
		rec->mt_mms_counts++;
  
		// ���Զ˺�����ֵʱ
		if(strlen(opp_num) > 0)
		{
			memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "F");
			strcat(rec->other_numbers, opp_num);

			// ������ϴ
			//opp_num_cleanout = numbers_cleanout(opp_num);
			// action_type: 1-��绰 ������ ������ 2-�ӵ绰 �Ӷ��� �Ӳ���
			//update_other_party_area(2, msisdn_cleanout, opp_num_cleanout, rec);				
		}
	}		
	else if((strcmp(event_type, "301") == 0) || (strcmp(event_type, "302") == 0) || (strcmp(event_type, "303") == 0) || (strcmp(event_type, "401") == 0) || (strcmp(event_type, "402") == 0))	// ����λ�ø��� 301����λ�ø��� 302����λ�ø��� 401 С���л�-���� 402 С���л�-�г�
	{
		// ����λ����Ϣ
		//rec->last_action_type = event_type;
		//strcpy(rec->last_action_type, event_type);
		
		// ����ͣ��ʱ�� ��ǰʱ��-����ʱ��
		//ʹ�õ�ǰ��������ʱ���-����ʱ���׼ȷ
		//rec->resident_time = (event_time - rec->come_time)/60;
		//rec->resident_time = (curr_system_time - rec->come_time)/60;
		//printf("rec->resident_time=[%d] chk.resident_time_raft=[%d]\n", rec->resident_time, chk.resident_time_raft);
	}
	else if(strcmp(event_type, "501") == 0)	// ����
	{
		rec->mobile_status = '2';
	}
	else if(strcmp(event_type, "502") == 0)	// �ػ�
	{
		rec->mobile_status = '1';
	}
		
	strcpy(rec->last_action_type, event_type);
  
  GetResultStr(rec, 0, str_result_tmp);

	//printf("ruleid=[%d] str_result_tmp=%s", ruleid, str_result_tmp);
	  	
  pthread_mutex_lock(&filtrate_mutex);
	// ���������ļ���

	WriteResult(ruleid, str_result_tmp);		
	pthread_mutex_unlock(&filtrate_mutex);
	
	//printf("after GetResultStr() rec->last_cell=[%s] \n",rec->last_cell);	
	// -------------------------------------------------------
	// -------------- �޸���������Ϣ��ʼ ---------------------
	// -------------------------------------------------------

	return ret;	
}

/*
// ������ϴ
// 1. ����86��0086��ͷʱ��ȥ��
// 2. a. ȡ��1��������ĺ��룬
//	  b. ���䳤�ȴ���8ʱ�����С��8λ��ȡ��ʵ�ʳ��ȣ���ȡǰ8λ�����С��8λ��ȡ��ʵ�ʳ��ȣ��ַ�������Ϊi, ��DIM_NUMBERS_PREFIX_INFO�в���
//	  c. ��b��û�в��ҵ�ʱ����i--
//	  d. if(i<3) �˳�����
// 3. ���2����ƥ����ַ�����ȥ���������ٴμ���Ƿ���86��0086��ͷʱ��ȥ��
char* numbers_cleanout(char* numbers)
{
	char* buffer = NULL;
	char* ret_buffer = NULL;
	char* buffer_tmp = NULL;
	
	int ret;

	if(memcmp(numbers,"0086",4) == 0)
	{
		buffer = numbers+4;
	}
	else if( memcmp(numbers,"86",2) == 0)
	{
		buffer = numbers+2;
	}
	else 
	{
		buffer = numbers;
	}

	ret = find_prefix_info(buffer);
	//printf("ret=[%d]\n", ret);
	if((ret >3) && (ret < strlen(buffer)))
	{
		buffer_tmp = buffer+ret;
	}
	else
	{
		buffer_tmp = buffer;
	}

	if(memcmp(buffer_tmp,"0086",4) == 0)
	{
		ret_buffer = buffer_tmp+4;
	}
	else if( memcmp(buffer_tmp,"86",2) == 0)
	{
		ret_buffer = buffer_tmp+2;
	}
	else 
	{
		ret_buffer = buffer_tmp;
	}

	//printf("ret_buffer=[%s]\n", ret_buffer);

	// ����ϴ��ĺ��볤��С�ڵ���3ʱ��˵����ϴ�����⣬��ԭ���뷵��
	if(strlen(ret_buffer) <= 3)
	{
		return numbers;
	}
	else
	{
		return ret_buffer;
	}
}
*/

/*
int update_user_other_numbers(char* event_type, char *opp_num, char *opp_num_cleanout, Context *rec, char *str_result_tmp)
{
	int ret = 0;
	char str_prefix[3];

	time_t curr_system_time;
	char str_curr_system_time[20];

	char lac_ci_id[20];

	struct tm *tp;

	// ʹ����ϴ��ĺ����ж����Ƿ����ط�������Ϣ����
	ret = find_spec_services_info(opp_num_cleanout);
	if(ret == 0)
	{
		//printf("û�ҵ�\n");
		return -1;
	}
	//printf("�ҵ�\n");

	// ���ļ��������ʹ��ԭ�к���
	memset(str_prefix, '\0', sizeof(str_prefix));
	if(strcmp(event_type, "201") == 0)
	{
		strcpy(str_prefix, "A");
	}
	else if(strcmp(event_type, "202") == 0)
	{
		strcpy(str_prefix, "B");
	}
	else if(strcmp(event_type, "203") == 0)
	{
		strcpy(str_prefix, "C");
	}
	else if(strcmp(event_type, "204") == 0)
	{
		strcpy(str_prefix, "D");
	}	
	
	
	
	if((strlen(rec->other_numbers) + strlen(opp_num) + 3) > MAX_OTHER_NUMBERS_LEN)
	{
		// ȡ��ϵͳ��ǰʱ��
		memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
		time(&curr_system_time);
		tp = localtime(&curr_system_time);
		sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
		tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
		//printf("str_curr_system_time=[%s]\n", str_curr_system_time);
		
		// ����ͣ��ʱ��
		rec->resident_time = (curr_system_time - rec->come_time)/60;

		// �жϵ�ǰ�û���Ӧ��С����Ϣ�Ƿ����߼�������
		pthread_mutex_lock(&filtrate_mutex);
		memset(lac_ci_id, '\0', sizeof(lac_ci_id));
		strncpy(lac_ci_id, rec->last_cell, 11);
		int res_physical_area = 0;
		res_physical_area = find_physical_area(lac_ci_id);
    	if(res_physical_area != 0)
   		{
			// ȡ���л�ǰ����������Ϣ
			GetResultStr(rec, 0, str_result_tmp);
			//printf("str_result_tmp=[%s]\n", str_result_tmp);				
			
			ret=1;
		}
		else
		{
			ret=0;
		}

		// �����ǰ��������Ϣ�е�other_numbers�ֶ�����
		memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
		strcpy(rec->other_numbers, str_prefix);
		strcat(rec->other_numbers, opp_num);
		strcat(rec->other_numbers, "|");
		//printf("���imsi=[%s] ��other_numbers�ֶ�����\n", imsi);

		pthread_mutex_unlock(&filtrate_mutex);
	}
	else
	{	
		// ȡ��calling_call_numbers
		strcat(rec->other_numbers, str_prefix);
		strcat(rec->other_numbers, opp_num);
		strcat(rec->other_numbers, "|");
	}

	//strcpy(str_result_tmp, (rec->other_numbers).c_str());
	//printf("imsi=[%s] �� rec->other_numbers=[%s]\n", imsi, rec->other_numbers);
	
	return ret;	
}


void update_other_party_area(int action_type, char *msisdn_cleanout, char * opp_num_cleanout, Context *rec)
{
	char opp_area_code[5];
	int opp_area_type = 0;

	char msisdn_4[5];
	char msisdn_3[4];

	char opp_area_info[10];

	// ȡ�ñ��˺ͶԶ�ȡ����Ϣ
	// ��ʽ���������ͣ�1λ��@���Ŵ��루����0��ȥ����2-3λ��
	// ������2@551
	int opp_area_flag = 0; // ��ʶ�Ƿ��ҵ��Զ˺����������Ϣ

	memset(opp_area_info, '\0', sizeof(opp_area_info));
	
	//printf("msisdn_cleanout=[%s] opp_num_cleanout=[%s]\n", msisdn_cleanout, opp_num_cleanout);


	// ��������ж�
	// ��"00"��ͷ���룬���������ǹ����Ǹ�����
	if(strncmp(opp_num_cleanout, "00", 2)  == 0)
	{
		opp_area_flag = 1;
		strcpy(opp_area_info, "4@00");
		//printf("msisdn_cleanout=[%s] opp_num_cleanout=[%s] opp_area_code=[%s]\n", msisdn_cleanout, opp_num_cleanout,opp_area_code);
	}
	else if((strncmp(opp_num_cleanout, "0", 1) == 0) && (strncmp(opp_num_cleanout, "00", 2) != 0) && (strlen(opp_num_cleanout) > 5))
	{
		// �ж���ع̶��绰�����׼
		// ���Զ˺�����"0"��ͷ���Ҳ���"00"��ͷ,���ҳ��ȴ���5ʱ,ȡ�ö�Ӧ�ĳ�;����
		memset(msisdn_4, '\0', sizeof(msisdn_4));
		strncpy(msisdn_4, opp_num_cleanout, 4);
		LTrim(msisdn_4, '0');

		memset(msisdn_3, '\0', sizeof(msisdn_3));
		strncpy(msisdn_3, opp_num_cleanout, 3);
		LTrim(msisdn_3, '0');
		
		//printf("msisdn_4=[%s] msisdn_3=[%s]\n", msisdn_4, msisdn_3);
		//printf("m_pstn_area_info[%d]=[%d]\n", atol(msisdn_4), m_pstn_area_info[atol(msisdn_4)]);
		//printf("m_pstn_area_info[%d]=[%d]\n", atol(msisdn_3), m_pstn_area_info[atol(msisdn_3)]);
		
		memset(opp_area_code, '\0', sizeof(opp_area_code));
		opp_area_type = m_pstn_area_info[atol(msisdn_4)];
		if( opp_area_type == 0)
		{
			opp_area_type = m_pstn_area_info[atol(msisdn_3)];
			if(opp_area_type == 0)
			{
				opp_area_type = 0;
				//printf("�Զ�Ϊ�̻�ʱ[%s]δ�ҵ����Ӧ��Ϣ��\n", opp_num_cleanout);
			}
			else
			{
				opp_area_flag = 1;
				strcpy(opp_area_code, msisdn_3);
			}
		}
		else
		{
			opp_area_flag = 1;
			strcpy(opp_area_code, msisdn_4);
		}
		
		//printf("opp_area_code=[%s] opp_area_type=[%d]\n", opp_area_code, opp_area_type);
		sprintf(opp_area_info, "%d@%s", opp_area_type, opp_area_code);
		//printf("�Զ�Ϊ�̻�ʱ����������Ϣ��opp_area_info=[%s]\n", opp_area_info);
	}
	else if((strncmp(opp_num_cleanout, "1", 1) == 0) && (strlen(opp_num_cleanout) == 11))
	{
		// �ж��ֻ������׼
		// ���Զ˺�����"1"��ͷ���ҳ��ȵ���11ʱ
		int ret_find_msisdn = find_msisdn_area_info(opp_num_cleanout);
		//printf("m_msisdn_info[%d]=[%s]\n", ret_find_msisdn, m_msisdn_info[ret_find_msisdn]);
		
		if(ret_find_msisdn != -1)
		{
			strcpy(opp_area_info, m_msisdn_info[ret_find_msisdn]+8);
			//printf("�Զ�Ϊ�ֻ�ʱ����������Ϣ��opp_area_info=[%s]\n", opp_area_info);
			
			opp_area_flag = 1;
		}
		else
		{
			//printf("�Զ�Ϊ�ֻ�ʱ[%s]δ�ҵ������������Ķ�Ӧ��Ϣ��\n", opp_num_cleanout);
		}
	}
	else
	{
		//printf("���ж϶Զ˺���[%s]��������Ϣʱ���Զ˺����ʽ�������жϱ�׼��\n", opp_num_cleanout);
	}

	// ���Զ˺����ҵ���������Ϣʱ
	if(opp_area_flag == 1)
	{
		// calling_other_party_area��called_other_party_area��ʽ��
		// ��ʽ���������ͣ�1λ��@���Ŵ��루����0��ȥ����2-3λ��
		// ������2@551 ��2-ʡ�� 3-ʡ�� 4-���⣩

		// ���ݴ�����¼�����,���в�ͬ����
		if(action_type == 1)	// ��绰 ������ ������
		{
				memset(rec->calling_other_party_area, '\0', sizeof(rec->calling_other_party_area));
				strcat(rec->calling_other_party_area, opp_area_info);
		}
		else	// �ӵ绰 �Ӷ��� �Ӳ���
		{
				memset(rec->called_other_party_area, '\0', sizeof(rec->called_other_party_area));
				strcpy(rec->called_other_party_area, opp_area_info);
		}
	}
	
	//printf("in update_other_party_area,opp_area_info=[%s],opp_num_cleanout=[%s] \n", opp_area_info,opp_num_cleanout);
}

void update_other_party_area111(int action_type, char *msisdn_cleanout, char * opp_num_cleanout, Context *rec)
{
	char opp_area_code[5];
	int opp_area_type = 0;

	char msisdn_4[5];
	char msisdn_3[4];

	char opp_area_info[10];
	char msisdn_area_info[10];

	// ȡ�ñ��˺ͶԶ�ȡ����Ϣ
	// ��ʽ���������ͣ�1λ��@���Ŵ��루����0��ȥ����2-3λ��
	// ������2@551
	int opp_area_flag = 0;

	//printf("msisdn_cleanout=[%s] opp_num_cleanout=[%s]\n", msisdn_cleanout, opp_num_cleanout);

	opp_area_flag = 0;	// ��ʶ�Ƿ��ҵ��Զ˺����������Ϣ
	memset(opp_area_info, '\0', sizeof(opp_area_info));
	// ��������ж�
	// ��"00"��ͷ�ĺ��룬���������ǹ����Ǹ�����
	if(strncmp(opp_num_cleanout, "00", 2) == 0)
	{
		strcpy(opp_area_code, "4@00");
	}
	// �ж���ع̶��绰�����׼
	// ���Զ˺�����"0"��ͷ���Ҳ���"00"��ͷ,���ҳ��ȴ���5ʱ,ȡ�ö�Ӧ�ĳ�;����
	else if((strncmp(opp_num_cleanout, "0", 1) == 0) && (strncmp(opp_num_cleanout, "00", 2) != 0) && (strlen(opp_num_cleanout) > 5))
	{
		memset(msisdn_4, '\0', sizeof(msisdn_4));
		strncpy(msisdn_4, opp_num_cleanout, 4);
		LTrim(msisdn_4, '0');

		memset(msisdn_3, '\0', sizeof(msisdn_3));
		strncpy(msisdn_3, opp_num_cleanout, 3);
		LTrim(msisdn_3, '0');
		
		//printf("msisdn_4=[%s] msisdn_3=[%s]\n", msisdn_4, msisdn_3);
		//printf("m_pstn_area_info[%d]=[%d]\n", atol(msisdn_4), m_pstn_area_info[atol(msisdn_4)]);
		//printf("m_pstn_area_info[%d]=[%d]\n", atol(msisdn_3), m_pstn_area_info[atol(msisdn_3)]);
		
		memset(opp_area_code, '\0', sizeof(opp_area_code));
		opp_area_type = m_pstn_area_info[atol(msisdn_4)];
		if( opp_area_type == 0)
		{
			opp_area_type = m_pstn_area_info[atol(msisdn_3)];
			if(opp_area_type == 0)
			{
				opp_area_type = 0;
				//printf("�Զ�Ϊ�̻�ʱ[%s]δ�ҵ����Ӧ��Ϣ��\n", opp_num_cleanout);
			}
			else
			{
				opp_area_flag = 1;
				strcpy(opp_area_code, msisdn_3);
			}
		}
		else
		{
			opp_area_flag = 1;
			strcpy(opp_area_code, msisdn_4);
		}
		
		//printf("opp_area_code=[%s] opp_area_type=[%d]\n", opp_area_code, opp_area_type);
		sprintf(opp_area_info, "%d@%s", opp_area_type, opp_area_code);
		//printf("�Զ�Ϊ�̻�ʱ����������Ϣ��opp_area_info=[%s]\n", opp_area_info);
	}
	// �ж��ֻ������׼
	// ���Զ˺�����"1"��ͷ���ҳ��ȵ���11ʱ
	else if((strncmp(opp_num_cleanout, "1", 1) == 0) && (strlen(opp_num_cleanout) == 11))
	{
		int ret_find_msisdn = find_msisdn_area_info(opp_num_cleanout);
		//printf("m_msisdn_info[%d]=[%s]\n", ret_find_msisdn, m_msisdn_info[ret_find_msisdn]);
		
		if(ret_find_msisdn != -1)
		{
			strcpy(opp_area_info, m_msisdn_info[ret_find_msisdn]+8);
			//printf("�Զ�Ϊ�ֻ�ʱ����������Ϣ��opp_area_info=[%s]\n", opp_area_info);
			
			opp_area_flag = 1;
		}
		else
		{
			//printf("�Զ�Ϊ�ֻ�ʱ[%s]δ�ҵ������������Ķ�Ӧ��Ϣ��\n", opp_num_cleanout);
		}
	}
	else
	{
		//printf("���ж϶Զ˺���[%s]��������Ϣʱ���Զ˺����ʽ�������жϱ�׼��\n", opp_num_cleanout);
	}

	// �ҵ��Զ˺����������Ϣ
	memset(msisdn_area_info, '\0', sizeof(msisdn_area_info));
	if(opp_area_flag == 1)
	{
		if((strncmp(msisdn_cleanout, "1", 1) == 0) && (strlen(msisdn_cleanout) == 11))
		{
			int ret_find_msisdn = find_msisdn_area_info(msisdn_cleanout);
			//printf("m_msisdn_info[%d]=[%s]\n", ret_find_msisdn, m_msisdn_info[ret_find_msisdn]);
		
			if(ret_find_msisdn != -1)
			{
				strcpy(msisdn_area_info, m_msisdn_info[ret_find_msisdn]+8);
				//printf("��������������Ϣ��msisdn_area_info=[%s]\n", msisdn_area_info);
			}
			else
			{
				//printf("���˺���[%s]��������δ�ҵ����Ӧ��Ϣ��\n", msisdn_cleanout);
			}
		}
		else
		{
			//printf("���ж϶Զ˺���[%s]��������Ϣʱ�����˺����ʽ�������жϱ�׼��\n", opp_num_cleanout);
		}
	}

	// ���Զ˺����ҵ���������Ϣʱ
	if(opp_area_flag == 1)
	{
		//printf("�Զ˺����������Ϣ[%s] ���˺����������Ϣ[%s]\n", opp_area_info, msisdn_area_info);
		
		// �жϱ��˺�����Զ˺���Ĺ������Ƿ���ͬ
		// ������ͬʱ����Ϊ�Զ�Ϊ����û�
		// calling_other_party_area��called_other_party_area��ʽ��
		// ��ʽ���������ͣ�1λ��@���Ŵ��루����0��ȥ����2-3λ��
		// ������2@551 ��2-ʡ�� 3-ʡ�� 4-���⣩
		if(strcmp(opp_area_info, msisdn_area_info) != 0)
		{
			// ���ݴ�����¼�����,���в�ͬ����
			if(action_type == 1)	// ��绰
			{
				if((strlen(rec->calling_other_party_area) + strlen(opp_area_info) + 2) > MAX_AREA_LEN)
				{
					//printf("action_type=[%d]\n", action_type);
					// �����ǰ��������Ϣ�е�other_numbers�ֶ�����
					memset(rec->calling_other_party_area, '\0', sizeof(rec->calling_other_party_area));

					strcpy(rec->calling_other_party_area, opp_area_info);
					strcat(rec->calling_other_party_area, "|");
				}
				else
				{	
					strcat(rec->calling_other_party_area, opp_area_info);
					strcat(rec->calling_other_party_area, "|");
				}
			}
			else	// �ӵ绰
			{
				if((strlen(rec->called_other_party_area) + strlen(opp_area_info) + 2) > MAX_AREA_LEN)
				{
					//printf("action_type=[%d]\n", action_type);
					// �����ǰ��������Ϣ�е�other_numbers�ֶ�����
					memset(rec->called_other_party_area, '\0', sizeof(rec->called_other_party_area));

					strcpy(rec->called_other_party_area, opp_area_info);
					strcat(rec->called_other_party_area, "|");
				}
				else
				{	
					strcat(rec->called_other_party_area, opp_area_info);
					strcat(rec->called_other_party_area, "|");
				}				
			}
		}
	}
}
*/

// time_flag=1ʱ���뿪ʱ��ȡϵͳ��ǰʱ��
// time_flag=0ʱ���뿪ʱ��ȡrec�ж�Ӧ�ֶε�ʱ��
int GetResultStr(Context *rec, int time_flag, char *str_result_tmp)
{
	char line[BIG_MAXLINE];
	char msisdn[16],last_cell[20],ca[3],tmp[BIG_MAXLINE];
	char str_other_numbers[BIG_MAXLINE], str_tmp[BIG_MAXLINE];
	char str_calling_other_numbers[BIG_MAXLINE], str_called_other_numbers[BIG_MAXLINE];
	char str_smo_other_numbers[BIG_MAXLINE], str_smt_other_numbers[BIG_MAXLINE];
	char str_mmo_other_numbers[BIG_MAXLINE], str_mmt_other_numbers[BIG_MAXLINE];
		
	int calling_other_numbers_flag=0, called_other_numbers_flag=0, smo_other_numbers_flag=0, smt_other_numbers_flag=0;
	struct tm *tp;
	
	int mobile_open_counts=0,mobile_close_counts=0;

	// ȡ��ϵͳ��ǰʱ��
	time_t curr_system_time;
	char str_curr_system_time[20];
	memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
	time(&curr_system_time);
	tp = localtime(&curr_system_time);
	sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_curr_system_time=[%s]\n", str_curr_system_time);
  

	memset(line, '\0', sizeof(line));

	strcpy(line, rec->msisdn);
	strcat(line,",");
	
	//====================================================
	//========== ��lac_id,ci_id����ʼ ==================
	//====================================================
	//strncat(line, rec->last_cell, 11);
	//strcat(line,",");

	memset(last_cell, '\0', sizeof(last_cell));
	//printf("000 rec->last_cell=[%s] last_cell=[%s]\n", rec->last_cell, last_cell);
	strncat(last_cell, rec->last_cell, 11);
	//printf("111 rec->last_cell=[%s] last_cell=[%s] line=%s \n", rec->last_cell, last_cell,line);
	
	//���¼�����Ϊ601��602 ����ʱ lac,cellΪ�գ���Ҫ��ӿ�ֵ
	if( strncmp(last_cell, "-",1) == 0 )
	{
		strcat(line,",");
	} 
		else
	{
		strcat(line, last_cell);
		strcat(line,",");
	}
	
  //��������¼�ʱ�� ������ʵʱӪ��ʹ�� 20091117
	if(rec->ler_time != 0)
	{
		tp = localtime(&(rec->ler_time));
		sprintf(tmp, "%4d-%02d-%02d %02d:%02d:%02d,",
		tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
		strcat(line, tmp);
	}
	else
	{
		strcat(line, ",");
	}
		
	/*	xiamw 20100120 lac-cell �������	
	//���¼�����Ϊ601 ����ʱ lac,cellΪ�գ���Ҫ��ӿ�ֵ
	if( strncmp(last_cell, "-",1) == 0 )
	{
		strcat(line,",,");
	} 
	
	char* p_field_last_cell = NULL;
	p_field_last_cell = strtok(last_cell, "-");
	while(p_field_last_cell)
	{
		strcat(line, p_field_last_cell);
		strcat(line,",");
	
		p_field_last_cell = strtok(NULL, "-");
	}
	*/
	
	//printf("222 rec->last_cell=[%s] last_cell=[%s] line=%s \n", rec->last_cell, last_cell,line);
	//====================================================
	//========== ��lac_id,ci_id������� ==================
	//====================================================
	
	//������ǰ�ֻ�״̬���ֶ� ����Ϊ2ʱ������Ϊ1
	if(rec->mobile_status == '2')
	{
		mobile_open_counts = 1;
	}
	else if(rec->mobile_status == '1')
	{
		mobile_close_counts = 1;
	}

	sprintf(tmp,"%d,",mobile_open_counts);
	strcat(line, tmp);

	sprintf(tmp,"%d,",mobile_close_counts);
	strcat(line, tmp);
	
	sprintf(tmp,"%d,",rec->smo_sms_counts);
	strcat(line, tmp);
	
	sprintf(tmp,"%d,",rec->smt_sms_counts);
	strcat(line, tmp);
	
	sprintf(tmp,"%d,",rec->mo_mms_counts);
	strcat(line, tmp);

	sprintf(tmp,"%d,",rec->mt_mms_counts);
	strcat(line, tmp);
	
	sprintf(tmp,"%d,",rec->calling_call_counts);
	strcat(line, tmp);
	
	sprintf(tmp,"%d,",rec->called_call_counts);
	strcat(line, tmp);	
	
	sprintf(tmp,"%d,",rec->calling_call_duration);
	strcat(line, tmp);

	sprintf(tmp,"%d,",rec->called_call_duration);
	strcat(line, tmp);
	
	/*	
	// ȡ�öԶκ�����Ϣ������ֱ�Ӷ��ڴ��������Ҫ����
	pthread_mutex_lock(&chk.mutex);
	string other_numbers;
	map<string, InfoStat>::iterator m_PosNumber_Info;
	// ����imsi��Ϣ����
	m_PosNumber_Info = m_Number_Info.find(rec.imsi);
	// �����ڶԶκ�����Ϣʱ��ȡ�÷���rec��
	if(m_PosNumber_Info != m_Number_Info.end())
	{
		other_numbers = m_PosNumber_Info->second.other_numbers;
		
		// ɾ�����һ������
		other_numbers.erase(other_numbers.size()-1);
		//printf("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeevvv      other_numbers=[%s]\n", other_numbers.c_str());
	}

	strcat(line, other_numbers.c_str());
	strcat(line, "|");
	pthread_mutex_unlock(&chk.mutex);
	*/

	//==========================================================================
	//=========================== �Զκ��봦��ʼ =============================
	//==========================================================================
	char* p_field = NULL;

	//printf("rec->other_numbers=[%s]\n", rec->other_numbers);
	memset(str_other_numbers, '\0', sizeof(str_other_numbers));
	memset(str_calling_other_numbers, '\0', sizeof(str_calling_other_numbers));
	memset(str_called_other_numbers, '\0', sizeof(str_called_other_numbers));
	memset(str_smo_other_numbers, '\0', sizeof(str_smo_other_numbers));
	memset(str_smt_other_numbers, '\0', sizeof(str_smt_other_numbers));
	memset(str_mmo_other_numbers, '\0', sizeof(str_mmo_other_numbers));
	memset(str_mmt_other_numbers, '\0', sizeof(str_mmt_other_numbers));
		
		if(strlen(rec->other_numbers) > 2)
	{
		/*
		memset(str_tmp, '\0', sizeof(str_tmp));
		strcpy(str_tmp, rec->other_numbers);
		if(str_tmp[strlen(str_tmp)-1] == ',')
		{
			strncpy(str_other_numbers, str_tmp, strlen(str_tmp)-1);
		}
		else
		{
			strncpy(str_other_numbers, str_tmp, strlen(str_tmp));
		}
		*/
		
		p_field = strtok(rec->other_numbers, "|");
		
		//printf("p_field=[%s]\n", p_field);
		if(p_field[0] == 'A')
		{
			strcat(str_calling_other_numbers, p_field+1);
			//printf("str_calling_other_numbers=[%s]\n", str_calling_other_numbers);
			
			//calling_other_numbers_flag = 1;
		}
		else if (p_field[0] == 'B')
		{
			strcat(str_called_other_numbers, p_field+1);
			//printf("str_called_other_numbers=[%s]\n", str_called_other_numbers);
			
			//called_other_numbers_flag = 1;
		}
		else if (p_field[0] == 'C')
		{
			strcat(str_smo_other_numbers, p_field+1);
			//printf("str_smo_other_numbers=[%s]\n", str_smo_other_numbers);
			
			//smo_other_numbers_flag = 1;
		}	
		else if (p_field[0] == 'D')
		{
			strcat(str_smt_other_numbers, p_field+1);
			//printf("str_smt_other_numbers=[%s]\n", str_smt_other_numbers);
			
			//smt_other_numbers_flag = 1;
		}	
		else if (p_field[0] == 'E')
		{
			strcat(str_mmo_other_numbers, p_field+1);
		}	
		else if (p_field[0] == 'F')
		{
			strcat(str_mmt_other_numbers, p_field+1);
		}	
	}
	
	sprintf(tmp,"%s,", str_calling_other_numbers);
	strcat(line, tmp);

	sprintf(tmp,"%s,", str_called_other_numbers);
	strcat(line, tmp);

	sprintf(tmp,"%s,", str_smo_other_numbers);
	strcat(line, tmp);

	sprintf(tmp,"%s,", str_smt_other_numbers);
	strcat(line, tmp);

	sprintf(tmp,"%s,", str_mmo_other_numbers);
	strcat(line, tmp);

	sprintf(tmp,"%s,", str_mmt_other_numbers);
	strcat(line, tmp);
	
	//printf("str_calling_other_numbers=[%s] str_called_other_numbers=[%s] str_smo_other_numbers=[%s] str_smt_other_numbers=[%s]\n", str_calling_other_numbers,str_called_other_numbers,str_smo_other_numbers,str_smt_other_numbers);

	//==========================================================================
	//=========================== �Զκ��봦����� =============================
	//==========================================================================	

	/*
	if(strlen(rec->calling_other_party_area) > 2)
	{
		sprintf(tmp,"%s,", rec->calling_other_party_area);
		strcat(line, tmp);
	}
	else
	{
		strcat(line, ",");
	}

	if(strlen(rec->called_other_party_area) > 2)
	{
		sprintf(tmp,"%s,", rec->called_other_party_area);
		strcat(line, tmp);
	}
	else
	{
		strcat(line, ",");
	}
	*/

	//�����ʡ����ʡ��ʶ 1��ʾ��ʡ 0 ��ʾ��ʡ
	sprintf(tmp,"%s,",rec->local_prov_flag);
	strcat(line, tmp);
	
	//���ʡ��-���б���	
	strcat(line, rec->prov_code);
	strcat(line,"-");		
	strcat(line, rec->city_code);
	strcat(line,",");		

	//����¼����� �����ڼ�ʱӪ��ʹ�� 20091117
	sprintf(tmp,"%s,",rec->last_action_type);
	strcat(line, tmp);
	//�����¼����ʹ����뿪�������ڼ�ʱӪ��ʹ�� 20091117
	
	//����¼�ԭ���� 20100118
	sprintf(tmp,"%s",rec->cause);
	strcat(line, tmp);
	//�����¼�ԭ���� 20100118
	
	//������з�
	strcat(line, "\n");
	
  //�������ϵͳʱ�䣬��Ϊ��������¼�ʱ�� �����ڼ�ʱӪ��ʹ�� 20091117	
	/*
	sprintf(tmp,"%s\n", str_curr_system_time);
	strcat(line, tmp);
	*/

	strcpy(str_result_tmp, line);

	return 1;
}


int WriteResult(int ruleid, char *src)
{
	char *dest;
	char tmp[500];
	size_t	left,from;
	int ret;

	left=strlen(src);
	from=0;

	pthread_mutex_lock( &ana.mutex[ruleid]);

	dest=ana.fbuf+ruleid*FBUFFSIZE;

	while( left>0 ) {
		ana.counts[ruleid] ++;
		if(left+ana.num[ruleid] <= FBUFFSIZE) {
			/*bcopy(src+from, dest+ana.num[ruleid], left);20090326*/
			memcpy(dest+ana.num[ruleid],src+from, left);
			ana.num[ruleid] += left;
			left = 0;
		}
		else {
			/*bcopy(src+from, dest+ana.num[ruleid], FBUFFSIZE-ana.num[ruleid]); 20090326*/
			memcpy(dest+ana.num[ruleid],src+from, FBUFFSIZE-ana.num[ruleid]);
			left -= (FBUFFSIZE- ana.num[ruleid]);
			from += (FBUFFSIZE- ana.num[ruleid]);

			if(ana.fd[ruleid]>0) WriteN(ana.fd[ruleid], dest, FBUFFSIZE);
			else
			{
				ana.fd[ruleid] = open(ana.fname[ruleid], O_APPEND|O_WRONLY|O_CREAT, 0644);
				if(ana.fd[ruleid]>0)  WriteN(ana.fd[ruleid], dest, FBUFFSIZE);
				else {
					perror("Can't open result file");
					exit(-1);
				}
			}
			/*bzero(dest, FBUFFSIZE);*/
			memset(dest, '\0', FBUFFSIZE);
			ana.num[ruleid]=0;
		}
	}

	if( ana.timeout[ruleid] == 1 ) 
	{
		ana.timeout[ruleid]=0;

    // ��timeoutʱ�䵽��������������ļ����������
		if( ana.counts[ruleid]>0 ) 
		{
			// ��timeoutʱ�䵽�������滹û��д������Ϣ����Ҫ������ļ���������
			if(ana.fd[ruleid]<=0)
			{
				ana.fd[ruleid] = open(ana.fname[ruleid], O_APPEND|O_WRONLY|O_CREAT, 0644);
			}
			//printf("1111 ana.num[ruleid]=[%d] dest=[%s]\n", ana.num[ruleid], dest);
			WriteN(ana.fd[ruleid], dest, ana.num[ruleid]);
			//WriteN_wld(ana.fd[ruleid], dest, ana.num[ruleid]);
			close(ana.fd[ruleid]);

			// ȡ��ϵͳ��ǰʱ��
			time_t sys_time;
			char str_sys_time[20];
			memset(str_sys_time, '\0', sizeof(str_sys_time));
			sys_time = get_system_time_2(str_sys_time);

			memset(tmp, '\0', sizeof(tmp));
			char fname_tmp[200];
			memset(fname_tmp, '\0', sizeof(fname_tmp));
			strncpy(fname_tmp, ana.fname[ruleid], strlen(ana.fname[ruleid])-4);
			sprintf(tmp, "%s_%s", fname_tmp, str_sys_time);
			
			//�����׺����Ϊ�գ���������ĸ��Ϊ"."ʱ���Զ���"."
			if((strlen(chk.output_file_suffix) >=1) && (strncmp(chk.output_file_suffix, ".", 1) != 0) )
			{
				strcat(tmp, ".");	
			}		
			strcat(tmp, chk.output_file_suffix);			
			rename(ana.fname[ruleid], tmp);

			/*bzero(dest, FBUFFSIZE);*/
			memset(dest, '\0', FBUFFSIZE);
			ana.fd[ruleid] = open(ana.fname[ruleid], O_APPEND|O_WRONLY|O_CREAT, 0644);
			ana.num[ruleid]=0;
			ana.counts[ruleid]=0;

			//load_table(tmp, ana.tabname[ruleid]);
			// ɾ��װ�سɹ����ļ�
			//remove(tmp);
		}
	}

  pthread_mutex_unlock( &ana.mutex[ruleid]);

	return 0;
}


void testFind(char *imsi)
{
	int ret;
	//char msisdn[12];
	char msisdn[16];

	ret=FindIMSI(imsi);
	printf("\nSearch imsi:%s result:%d",imsi,ret);
	if(ret != -1) {
		//BCD2Char( context[ret].msisdn, msisdn, 11);
		//BCD2Char( context[ret].msisdn, msisdn, MAX_BCD_MSISDN_NUMBERS);
		strcpy(msisdn, context[ret].msisdn);
		printf(" msisdn:%s",msisdn);
	}
	printf("\n");
}

void testGet( char *imsi)
{
	Context rec;
	int ret;
	struct tm *tp;

	printf("\nNow GetFromContext(\"%s\")\n",imsi);
	ret = GetFromContext(imsi, &rec);
	if( ret != 0 ) {
		printf("Can't find context of %s.\n",imsi);
		return;
	}

	printf("1  msisdn:%s\n", rec.msisdn);
	printf("2  imsi:%s\n", imsi);
	printf("3  last_cell:%s\n",rec.last_cell);
	printf("4  mobile_status:%c\n",rec.mobile_status);
	
	printf("5  smo_sms_counts:%d\n",rec.smo_sms_counts);
	printf("6  calling_call_counts:%d\n",rec.calling_call_counts);
	printf("7  calling_call_duration:%d\n",rec.calling_call_duration);
	printf("8  smt_sms_counts:%d\n",rec.smt_sms_counts);
	printf("9  called_call_counts:%d\n",rec.called_call_counts);
	printf("10 called_call_duration:%d\n",rec.called_call_duration);

	tp = localtime( &rec.come_time);
	printf("11 last_open:%4d.%02d.%02d %02d:%02d:%02d\n",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);

	tp = localtime( &rec.leave_time);
	printf("12 last_close:%4d.%02d.%02d %02d:%02d:%02d\n",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);

	printf("13 other_numbers:%s\n",rec.other_numbers);
	printf("14 resident_time:%d\n",rec.resident_time);
}

int main (int argc, char *argv[])
{
	int i;
	float size;
	pthread_t	tid_produce,tid_monitor;
	pthread_t	tid_backup,tid_init,tid_load,tid_log;
	pthread_t	*tid_consume;
	pthread_attr_t attr;

	Config *cfg;
	
	int ret;
  char buff[300];
	char errinfo[200];  
	
	cfg = (Config *)Malloc(sizeof(Config));
	ReadConfig("../../etc/c/smLocalContext.conf", cfg);

	// ���smLocalContext.conf�ļ�������Ϣ
	PrintCfg(cfg);
	
	/*
	//�������ݿ⣬���Ӳ������˳�
	ret = connect_db(cfg->db_name, cfg->db_user, cfg->db_passwd);	
  if (ret == -1 ) {
			exit(8);
	}
	*/
		
	chk.hash_tune=cfg->hash_tune;
	chk.analyze_thread_num=cfg->analyze_thread_num;
	chk.load_file_num=cfg->load_file_num;
	chk.direct_receive=cfg->direct_receive;
	strcpy(chk.table_name, cfg->table_name);
	strcpy(chk.select_cond,cfg->select_cond);
	
	chk.init_context_period=cfg->init_context_period;
	chk.init_context_day=cfg->init_context_day;		
	chk.init_context_hour=cfg->init_context_hour;
	chk.init_context_min=cfg->init_context_min;
	chk.backup_context_interval=cfg->backup_context_interval;

	strcpy(chk.physical_area_table_name, cfg->physical_area_table_name);
	strcpy(chk.physical_area_table_cel, cfg->physical_area_table_cel);

	chk.resident_time_raft=cfg->resident_time_raft;
	
	strcpy(chk.nonparticipant_file_path, cfg->nonparticipant_file_path);

	strcpy(chk.input_file_path, cfg->input_file_path);
	strcpy(chk.input_file_backup_path, cfg->input_file_backup_path);	
	chk.sleep_interval=cfg->sleep_interval;

	chk.event_type_filter=cfg->event_type_filter;
	chk.imsi_msisdn_flag=cfg->imsi_msisdn_flag;
	chk.agg_cell_flag=cfg->agg_cell_flag;
		
	strcpy(chk.msisdn_info_table_name, cfg->msisdn_info_table_name);
	strcpy(chk.pstn_area_info_table_name, cfg->pstn_area_info_table_name);
	strcpy(chk.numbers_prefix_info_table_name, cfg->numbers_prefix_info_table_name);
		
	strcpy(chk.load_file_prefix, cfg->load_file_prefix);
	strcpy(chk.output_file_suffix, cfg->output_file_suffix);
	
	chk.signal_sort_flag=cfg->signal_sort_flag;
	chk.signal_sort_capacity=cfg->signal_sort_capacity;
	chk.signal_sort_interval=cfg->signal_sort_interval;

	strcpy(chk.local_prov_code, cfg->local_prov_code);	
	chk.other_prov_flag=cfg->other_prov_flag;
	
					
	//if(chk.imsi_msisdn_flag != 0)
	//{
	//��������ɳ�ʼ�����þ���
	chk.context_capacity = cfg->context_capacity * 1000000 ;
			//chk.context_capacity = cfg->context_capacity * 1 ;			
	//}

	strcpy(chk.log_file_path, cfg->log_file_path);
	strcpy(chk.err_file_path, cfg->err_file_path);
	strcpy(chk.proc_file_path, cfg->proc_file_path);			
	strcpy(chk.host_code, cfg->host_code);	
	strcpy(chk.entity_type_code, cfg->entity_type_code);	
	strcpy(chk.entity_sub_code, cfg->entity_sub_code);	
	chk.log_interval=cfg->log_interval;		
  strcpy(chk.filename, cfg->filename);
  			
	free(cfg);

	/*
		printf("��ȡimsi��������Ϣ��ʼ...\n");
  	
		chk.context_capacity = count_rows(chk.table_name, chk.select_cond);
		
		//����ʹ�� 20091121 20091218
		//chk.context_capacity = 263;//349933;//25000000
		
		printf("��ȡimsi��������Ϣ����\n\n");
	*/

	time_t begin_time, end_time;
	char str_begin_time[20], str_end_time[20];
	memset(str_begin_time, '\0', sizeof(str_begin_time));
	begin_time = get_system_time(str_begin_time);
	//printf("str_begin_time=[%s]\n", str_begin_time);
	printf("�����Ŀռ��ڴ�������ʼ����ʼ str_begin_time=[%s]...\n", str_begin_time);
  
	// �����Ŀռ����
	context = (BCDContext *)Malloc(sizeof(BCDContext)*chk.context_capacity);
	
  if(!context)
  {	
  	printf("Not Enough Memory in context !\n");
  	exit(1);
  }
  	
	// �����Ŀռ��ʼ��
	/*bzero(context, sizeof(BCDContext)*chk.context_capacity);20090326*/
	memset(context, '\0', sizeof(BCDContext)*chk.context_capacity);
	
 	 			
	// �������ռ�������ʼ��
	Index = (BCDIndex *)Malloc(sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune));
	if(!Index)
  {	
  	printf("Not Enough Memory in Index !\n");
  }
  
	for(i=0; i<chk.context_capacity-chk.hash_tune; i++)
	{
		Index[i].offset=Index[i].redirect= -1;
	}

	/*
	if(chk.imsi_msisdn_flag == 0)
	{  		
 			// ���������ռ����
			#ifdef _DB2_
			//memset(filename, 0, sizeof(filename));
			//strcpy(filename, "imsi_msisdn_map.txt");
			
			export_file();
			chk.redirect_capacity = read_conflict_file(chk.filename);
			#endif //_DB2_ 
  		
			#ifdef _ORACLE_
			chk.redirect_capacity = read_conflict(chk.table_name, chk.select_cond);
			#endif //_ORACLE_ 	
				
			if( chk.redirect_capacity > 0 )
			{
				redirect = (BCDIndex *)Malloc(sizeof(BCDIndex)*chk.redirect_capacity);
			}
		
  }
  else
  {
  		chk.context_capacity_used = 0; 
  		chk.redirect_capacity = 0;
  		
  		//��������������ڴ�ռ�����������ڴ�ռ䲻���ʧ�ܣ�
  		//�ʶ�Ԥ�ȷ���͸�Ϊ��������һ���������ض��������ڴ�ռ䣬����ʱһ�η�����
			redirect = (BCDIndex *)Malloc(sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune));
			for(i=0; i<chk.context_capacity-chk.hash_tune; i++){
				redirect[i].offset=redirect[i].redirect= -1;
			}			 
	}
	*/

  chk.context_capacity_used = 0; 
  //chk.redirect_capacity = 0;
  
  //��������������ڴ�ռ�����������ڴ�ռ䲻���ʧ�ܣ�
  //�ʶ�Ԥ�ȷ���͸�Ϊ��������һ���������ض��������ڴ�ռ䣬����ʱһ�η�����
	redirect = (BCDIndex *)Malloc(sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune));
	for(i=0; i<chk.context_capacity-chk.hash_tune; i++){
		redirect[i].offset=redirect[i].redirect= -1;
	}		
			
					 		
	memset(str_end_time, '\0', sizeof(str_end_time));
	end_time = get_system_time(str_end_time);
	//printf("str_end_time=[%s]\n", str_end_time);
	printf("�����Ŀռ��ڴ�������ʼ������ str_end_time=[%s]\n\n", str_end_time);
  
	printf("��ʾ������ռ���ڴ���Ϣ��ʼ...\n");
	printf("sizeof(BCDContext) is %dB\n", sizeof(BCDContext));
	printf("sizeof(BCDIndex) is %dB.\n\n", sizeof(BCDIndex));
  
	printf("subscribers:%d\n", chk.context_capacity);
  
	size = sizeof(BCDContext)*chk.context_capacity;
	printf("������[Context]ռ���ڴ�:%.2f MB\n", size/1048576);
  
	size = sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune);
	printf("������������[Index]ռ���ڴ�:%.2f MB\n", size/1048576);
  
	//if(chk.imsi_msisdn_flag == 0)
	//{  
	//	size=sizeof(BCDIndex)*chk.redirect_capacity;
	//}
	//else 
	//{
	//	size=sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune);
	//}
	
	size=sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune);
	printf("�����ĸ�������[Reindex]ռ���ڴ�:%.2f MB\n", size/1048576);
	printf("��ʾ������ռ���ڴ���Ϣ����\n\n");
			
	if(chk.imsi_msisdn_flag == 0)
	{  				
			// ===================================================================================
			// ===================== ����imsi��msisdn��Ӧ��ϵ��Ϣ��ʼ ============================
			//====================================================================================
			memset(str_begin_time, '\0', sizeof(str_begin_time));
			begin_time = get_system_time(str_begin_time);
			//printf("str_begin_time=[%s]\n", str_begin_time);
			printf("����imsi��msisdn��Ӧ��ϵ��Ϣ��ʼ str_begin_time=[%s]...\n", str_begin_time);
			
			InitContext();
				
			memset(str_end_time, '\0', sizeof(str_end_time));
			end_time = get_system_time(str_end_time);
			//printf("str_end_time=[%s]\n", str_end_time);
			printf("����imsi��msisdn��Ӧ��ϵ��Ϣ���� str_end_time=[%s]\n\n", str_end_time);
			printf("conflict_subscribers:%d\n\n", chk.redirect_capacity);
			// ===================================================================================
			// ===================== ����imsi��msisdn��Ӧ��ϵ��Ϣ���� ============================
			//====================================================================================
	}
	
	 
	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
	
	PthreadCreate(&tid_init, NULL, init_timer, NULL);

	ana.fbuf = (char *)Malloc(chk.load_file_num * FBUFFSIZE);
	for(i=0; i<chk.load_file_num; i++) {	
		pthread_mutex_init(&ana.mutex[i], NULL);
		sprintf(ana.fname[i], "%s%02d.tmp", chk.load_file_prefix, i);
		//printf("ana.fname[%d]=[%s]\n", i+1, ana.fname[i]);
		ana.num[i]=0;
		ana.counts[i]=0;
		ana.fd[i]=-1;
		ana.timeout[i]=-1;
		ana.event_time_begin[i]=0;
		strcpy(ana.tabname[i], "mtl_ler_user_physical");
	}


	pthread_mutex_init(&pthread_init_mutex, NULL);

	pthread_mutex_init(&filtrate_mutex, NULL);

	pthread_mutex_init(&pthread_logfile_mutex,NULL);		
	

	//��ȡ�������ӳ��
	printf("�����Ӧ��ϵ...\n");
	read_decode_info();
	printf("�����Ӧ��ϵ����\n");


  /**********************************************************/
	/******** Ϊ�˱�֤��ʼ������ɣ�����һ��ʱ�� **************/
	/**********************************************************/
	//sleep(10);

  //���������������,д�����ļ�
  char moudleName[250] ;
  memset(moudleName,'\0',sizeof(moudleName));
  sprintf(moudleName,"%ssmLocalContext.proc",chk.proc_file_path);
  write_heart_file(moudleName);
  
  //��ȡ�����ݺ󣬼��ر����ݿ�����20110509
  //close_db();
  
	// ���ò��ú��ַ�ʽȡ����������
	//PthreadCreate(&tid_produce, &attr, produce_fr_tcp, NULL); // socked��tcp��ʽ
	PthreadCreate(&tid_produce, &attr, produce_fr_ftp, NULL); // ֱ�Ӷ�ftp���䵽ָ��Ŀ¼�µ��ļ���ʽ��ֻ�Ƕ�ȡ�ļ����֣�

	// ����load�߳�
	PthreadCreate(&tid_monitor, NULL, load_timer, NULL);

	// ���������߳�
	//PthreadCreate(&tid_backup, NULL, backup_timer, NULL);

	// ������ʱ�����־�߳�
	PthreadCreate(&tid_log, NULL, log_timer, NULL);
	
	// ���������߳�
	tid_consume=(pthread_t*)Malloc(chk.analyze_thread_num*sizeof(pthread_t));
	for(i=0; i<chk.analyze_thread_num; i++) 
	{
		PthreadCreate(tid_consume+i, &attr, consume, NULL);
	}
	

	// �ȴ��ɼ��̣߳������̣߳������Ĵ����߳̽���
	// ��ʼ���̣߳�����̲߳��ȴ������
	// ��������̲߳��ȴ��������������߳���������Ĺ����У��������ֹͣ�����ܻ���������¼������
	pthread_join(tid_produce, NULL);
	//pthread_join(tid_backup, NULL);

	
	for(i=0; i<chk.analyze_thread_num; i++)
	{
		pthread_join( *(tid_consume+i), NULL);
	}

	
	if(tid_consume != NULL) free(tid_consume);
	if(context != NULL) free(context);
	if(Index != NULL) free(Index);
	if(redirect != NULL) free(redirect);

	//close_db();

  //����־�������ʱ��Ϊ5���ӣ�Ӱ���˳����ʲ��ȴ�ֱ���˳�
	//pthread_join(tid_log, NULL);
	
	printf("�����˳���ʶ�������˳� \n");

	memset(errinfo,'\0',sizeof(errinfo));
	sprintf(errinfo,"�ͻ������˳�����������飡");		   
	write_error_file(chk.err_file_path,"smLocalContext","61",2,errinfo);	
	
	exit(0);
}


/*
int read_physical_area_info()
{
	// ȡ�ü�¼����
	int tmp_physical_area_num = 0;
	//physical_area_num = read_physical_area_num(chk.physical_area_table_name, chk.physical_area_table_cel);
	printf("physical_area_num=[%d]\n", tmp_physical_area_num);

	// ����ռ�
    m_physical_area=(char**)malloc((tmp_physical_area_num)*sizeof(*m_physical_area));
    *m_physical_area=(char*)malloc((tmp_physical_area_num)*21*sizeof(**m_physical_area));
    for(int i=0; i<(tmp_physical_area_num); i++)
    {
        m_physical_area[i]=*m_physical_area+21*i;
    }        
    
    for(int i=0; i<tmp_physical_area_num; i++)
    {
       memset(m_physical_area[i], '\0', 21);  
    }
    
	read_physical_area(chk.physical_area_table_name, chk.physical_area_table_cel);

	return tmp_physical_area_num;
}
*/


int read_event_type()
{
   /**********************************************************/
	/*************** ��ȡ�¼����Ϳ�ʼ *************************/
	/**********************************************************/
	char str_event_type[1024], str_event_type_tmp[1024];
	
	FILE *fp;
	
	int rec_num;

	set<string> m_event_type_tmp;
	set<string>::iterator 	m_pos_event_type_tmp;

	//pthread_mutex_lock(&filtrate_mutex);
	//printf("1111\n");
	fp = fopen("../../etc/c/event_type.list", "r");
	if(fp==NULL)
	{
		printf("���ļ�event_type.list����\n");


		exit(-1);
	}
	//printf("2222\n");

	memset(str_event_type_tmp, '\0', sizeof(str_event_type_tmp));
	memset(str_event_type, '\0', sizeof(str_event_type));
	while(fgets(str_event_type_tmp, 1024, fp)!=NULL)
	{
		//printf("3333 str_event_type_tmp=[%s]\n", str_event_type_tmp);
		if(str_event_type_tmp[strlen(str_event_type_tmp)-1] == '\n')
		{
			strncpy(str_event_type, str_event_type_tmp, strlen(str_event_type_tmp)-1);
		}
		else
		{
			strncpy(str_event_type, str_event_type_tmp, strlen(str_event_type_tmp));
		}

		if(str_event_type[0] == '#')
		{
			//pthread_mutex_unlock(&filtrate_mutex);
			memset(str_event_type_tmp, '\0', sizeof(str_event_type_tmp));
			memset(str_event_type, '\0', sizeof(str_event_type));

			continue;
		}

		if(strlen(str_event_type) > 10)
		{
			printf("str_event_type=[%s]���Ȳ��ܴ���10�ֽ�\n", str_event_type);
			printf("�����˳���\n");
			
			exit(-1);
		}

		//printf("str_event_type=[%s]\n", str_event_type);
		m_event_type_tmp.insert(str_event_type);

        //m_event_type_tmp.insert(make_pair(string(str_event_type), string(str_event_type)));

		//printf("3333 22\n");
		memset(str_event_type_tmp, '\0', sizeof(str_event_type_tmp));
		memset(str_event_type, '\0', sizeof(str_event_type));
		
		//printf("4444\n");
	}
	
	fclose(fp);
	
	/*
    for(m_pos_event_type_tmp=m_event_type_tmp.begin(); m_pos_event_type_tmp!=m_event_type_tmp.end(); ++m_pos_event_type_tmp)
    {
        printf("[%s]\n", (*m_pos_event_type_tmp).c_str());
    }

    printf("m_event_type_tmp.size()=[%d]\n", m_event_type_tmp.size());
	*/
	
	//pthread_mutex_unlock(&filtrate_mutex);

    /**********************************************************/
	/*************** ��ȡ�¼����ͽ��� *************************/
	/**********************************************************/	


    /**********************************************************/
	/************ �����ڴ��������Ϣ��ʼ **********************/
	/**********************************************************/
	rec_num = m_event_type_tmp.size();
	
    m_event_type=(char**)malloc((rec_num)*sizeof(*m_event_type));
    *m_event_type=(char*)malloc((rec_num)*11*sizeof(**m_event_type));
    for(int i=0; i<(rec_num); i++)
    {
        m_event_type[i]=*m_event_type+11*i;
    }        
    
    for(int i=0; i<rec_num; i++)
    {
       memset(m_event_type[i], '\0', 11);  
    }
    
    int i = 0;
    for(m_pos_event_type_tmp=m_event_type_tmp.begin(); m_pos_event_type_tmp!=m_event_type_tmp.end(); ++m_pos_event_type_tmp)
    {
		strcpy(m_event_type[i], (*m_pos_event_type_tmp).c_str());
		i++;
    }

	/*
    for(i=0; i<rec_num; i++)
    {
		printf("m_event_type[%d]=[%s]\n", i, m_event_type[i]);
    }
    */
    /**********************************************************/
	/************ �����ڴ��������Ϣ���� **********************/
	/**********************************************************/

    return rec_num;
}


void read_decode_info() 
{
	char str_decode_map[1024], str_decode_map_tmp[1024];
	
	DECODE_MAP			m_Stat;
		
	//set<DECODE_MAP, sort_decode_map> 			m_decode_map;
	//set<DECODE_MAP, sort_decode_map>::iterator 	m_pos_decode_map;

	set<DECODE_MAP> 			m_decode_map;
	set<DECODE_MAP>::iterator 	m_pos_decode_map;

	int	loop = 0;
	char* p_field = NULL;

	char		field_name[50];
	int			field_id;

	FILE *fp;

	fp = fopen("../../etc/c/smLocalContext_decode_map.conf", "r");
	if(fp==NULL)
	{
		printf("���ļ�decode_map.conf����\n");

		exit(-1);
	}
	
	memset(str_decode_map_tmp, '\0', sizeof(str_decode_map_tmp));
	memset(str_decode_map, '\0', sizeof(str_decode_map));
	while(fgets(str_decode_map_tmp, 1024, fp)!=NULL)
	{
		if(str_decode_map_tmp[strlen(str_decode_map_tmp)-1] == '\n')
		{
			strncpy(str_decode_map, str_decode_map_tmp, strlen(str_decode_map_tmp)-1);
		}
		else
		{
			strncpy(str_decode_map, str_decode_map_tmp, strlen(str_decode_map_tmp));
		}

		if(str_decode_map[0] == '#')
		{

			memset(str_decode_map_tmp, '\0', sizeof(str_decode_map_tmp));
			memset(str_decode_map, '\0', sizeof(str_decode_map));
		
			continue;
		}
		
		//printf("str_decode_map=[%s]\n", str_decode_map);
		loop = 0;
		p_field = strtok(str_decode_map, ",");
		while(p_field)
		{
			loop ++;
			
			LTrim(p_field, ' ');
			RTrim(p_field, ' ');
				
			if(loop == 1)
			{
				memset(field_name, '\0', sizeof(field_name));
				strcpy(field_name, p_field);
				//printf("field_name=[%s]\n", field_name);
			}
				
			if(loop == 2)
			{
				field_id = atoi(p_field);
				//printf("field_id=[%d]\n", field_id);
			}
				
			p_field = strtok(NULL, ",");
		}

		memset(&m_Stat, '\0', sizeof(m_Stat));
		strcpy(m_Stat.field_name, field_name);
		m_Stat.field_id = field_id;

		m_decode_map.insert(m_Stat);

		memset(str_decode_map_tmp, '\0', sizeof(str_decode_map_tmp));
		memset(str_decode_map, '\0', sizeof(str_decode_map));
	}
	
	fclose(fp);

	/*
	for(m_pos_decode_map=m_decode_map.begin(); m_pos_decode_map!=m_decode_map.end(); ++m_pos_decode_map)
    {
        printf("field_name=[%s] field_id=[%d]\n", m_pos_decode_map->field_name, m_pos_decode_map->field_id);
        
    }
	*/

	
	// ȡ��IMSI��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "imsi");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_imsi_num = m_pos_decode_map->field_id - 1;
		//printf("field_imsi_num=[%d]\n", field_imsi_num);
	}

	// ȡ��msisdn��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "msisdn");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		field_msisdn_num = m_pos_decode_map->field_id - 1;
	}
	
	// ȡ��event_type��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "event_type");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_event_type_num = m_pos_decode_map->field_id - 1;
		//printf("field_event_type_num=[%d]\n", field_event_type_num);
	}

	// ȡ��time_stamp��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "time_stamp");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_time_stamp_num = m_pos_decode_map->field_id - 1;
		//printf("field_time_stamp_num=[%d]\n", field_time_stamp_num);
	}
	
	// ȡ��duration��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "duration");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_duration_num = m_pos_decode_map->field_id - 1;
		//printf("field_duration_num=[%d]\n", field_duration_num);
	}

	// ȡ��lac_id��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "lac_id");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_lac_id_num = m_pos_decode_map->field_id - 1;
		//printf("field_lac_id_num=[%d]\n", field_lac_id_num);
	}

	// ȡ��ci_id��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "ci_id");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_ci_id_num = m_pos_decode_map->field_id - 1;
		//printf("field_ci_id_num=[%d]\n", field_ci_id_num);
	}
	
	// ȡ��cause��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "cause");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_cause_num = m_pos_decode_map->field_id - 1;
		//printf("field_cause_num=[%d]\n", field_cause_num);
	}
	
	// ȡ��other_party��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "other_party");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_other_party_num = m_pos_decode_map->field_id - 1;
		//printf("field_other_party_num=[%d]\n", field_other_party_num);
	}

	// ȡ��other_party��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "local_prov_flag");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_local_prov_flag_num = m_pos_decode_map->field_id - 1;
		//printf("field_local_prov_flag_num=[%d]\n", field_local_prov_flag_num);
	}
	
	// ȡ��other_party��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "prov_code");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_prov_code_num = m_pos_decode_map->field_id - 1;
		//printf("field_prov_code_num=[%d]\n", field_prov_code_num);
	}
	
	// ȡ��other_party��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "city_code");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_city_code_num = m_pos_decode_map->field_id - 1;
		//printf("field_city_code_num=[%d]\n", field_city_code_num);
	}
					
}


void read_nonparticipant_data() 
{
	int	fd;
	int  num=1;
	char line[MAXLINE];
	FileBuff fb;
	
	char buff[300];

	fb.num=0;
	fb.from=0;
	
	int ret = 0;

	DIR				*dp;
	struct dirent *entry;
	struct stat	buf;
	char		*ptr;
	#define MAXLINES 100
	char *fileptr[MAXLINES];

	char input_file_path[200];
	char input_file_backup_path[200];
	
	char input_file_name[200];

	set<string> 				m_input_file_name;
	set<string>::iterator 		m_pos_m_input_file_name;

	// ȡ�������ļ�·��
	memset(input_file_path, '\0', sizeof(input_file_path));
	strcpy(input_file_path, chk.nonparticipant_file_path);
	printf("input_file_path=[%s]\n", input_file_path);

			
	if((dp = opendir(input_file_path)) == NULL)
	{
		printf("·��[%s]�򿪴���\n", input_file_path);

		exit(-1);
	}
    else 
	{

		m_input_file_name.clear();
    
        while((entry = readdir(dp)) != NULL)
        {
        	memset(input_file_name, '\0', sizeof(input_file_name));
        	strcpy(input_file_name, input_file_path);
        	strcat(input_file_name, "/");
        	strcat(input_file_name, entry->d_name);
    
        	if((strcmp(input_file_name, ".")== 0) || (strcmp(input_file_name, "..")== 0))
			{
				continue;
			}
    
			printf("wld 1111 ��ǰ�ļ���[%s]\n", input_file_name);
    
			if (lstat(input_file_name, &buf) < 0)
			{
				continue;
			}
			
			if(strstr(input_file_name, ".tmp") != NULL){
		      continue;
	    }	
			//printf("wld 2222 ��ǰ�ļ���[%s]\n", input_file_name);
    
			if (!S_ISREG(buf.st_mode))
			{
				continue;
			}
    
			//printf("wld 2222 %s %ld %ld \n",input_file_name,buf.st_atime,buf.st_mtime);
			m_input_file_name.insert(entry->d_name);
    
		}  
    
		closedir(dp);
    
		//printf("ȡ��ÿһ���ļ���...\n");
		for(m_pos_m_input_file_name=m_input_file_name.begin(); m_pos_m_input_file_name!=m_input_file_name.end(); ++m_pos_m_input_file_name)
		{
			memset(input_file_name, '\0', sizeof(input_file_name));
        	strcpy(input_file_name, input_file_path);
        	strcat(input_file_name, "/");
        	strcat(input_file_name, m_pos_m_input_file_name->c_str());      
    
			time_t begin_time;                      
			char str_begin_time[20];        
			memset(str_begin_time, '\0', sizeof(str_begin_time));
			begin_time = get_system_time(str_begin_time);     
			//printf("str_begin_time=[%s]\n", str_begin_time);
    
			printf("��ǰ�����ļ� [%s] str_begin_time=[%s]\n", input_file_name, str_begin_time);
			fflush(stdout);
    
			// �����ļ��е�ÿ������
			fd=open(input_file_name, O_RDONLY);
			num = 1;
			while(num>0)
			{
				// ȡ���ļ��е�ÿ����¼
				num = ReadLine(fd, &fb, line, MAXLINE);	// ��num==0ʱ����ʾ�ѵ����ļ�β�����޿ɶ�ȡ������
    
				if( num >0 )
				{
					if( chk.direct_receive && Discard(line, 11))
					{
						continue;
					}
    
					pthread_mutex_lock(&lb.mutex);
					while ( lb.empty < MAXLINE)
					{
						pthread_cond_wait(&lb.less, &lb.mutex);
					}
    
					num=PutLine(line, &lb);
    
					pthread_cond_signal(&lb.more);
					pthread_mutex_unlock(&lb.mutex);
    
					//ss_num++;
				}
			}
    
			close(fd);
    
			// ɾ��������ɵ��ļ�
			memset(buff, 0, sizeof(buff));
			strcpy(buff, "rm -fr ");
			strcat(buff, input_file_name);
			printf("buff = [%s]\n", buff);
			system(buff);
		}
    
		if(exitflag>0)
		{
			m_input_file_name.clear();
				
			file_read_exitflag = 1;
    
			pthread_exit(0);
		}
	}
}



int  find_event_type(char *event_type)
{
    int         iRet = 0;
    int         iRet_DB = 0;

    int         lLeft = 0;
    long        lMiddle = 0;
    int         lRight = event_type_num - 1;
         
    // printf("\nevent_type = %s, lRight= %d\n", event_type, lRight);
   //  printf("strlen:%d",strlen(event_type));
          
	while(lLeft <= lRight)
    {
        lMiddle = (lLeft + lRight) / 2;
        
     //    printf("\nm_event_type[%d]: %s\n",lMiddle, m_event_type[lMiddle]);
     //    printf("strlen_m:%d",strlen(m_event_type[lMiddle]));
        
        iRet = memcmp(m_event_type[lMiddle], event_type, strlen(m_event_type[lMiddle]));
		    //printf("iRet=%d",iRet);
        if(iRet == 0)
        {
            return 1;
        }

        if(iRet < 0)
            lLeft = lMiddle + 1;
        else
            lRight = lMiddle - 1;
    }

	return 0;
	
}

/*
int  find_physical_area(char *physical_area)
{
    int         iRet = 0;
    int         iRet_DB = 0;

    int         lLeft = 0;
    long        lMiddle = 0;
    //int         lRight = physical_area_num - 1;
    int         lRight = 1;
         
	while(lLeft <= lRight)
    {
        lMiddle = (lLeft + lRight) / 2;
        iRet = memcmp(m_physical_area[lMiddle], physical_area, strlen(m_physical_area[lMiddle]));
		
        if(iRet == 0)
        {
            return 1;
        }

        if(iRet < 0)
            lLeft = lMiddle + 1;
        else
            lRight = lMiddle - 1;
    }

	return 0;
	
}


// ���ع��ڳ�;������Ϣ���ƶ��Ŷ���Ϣ
int read_area_info()
{

	memset(&m_pstn_area_info, '\0', sizeof(m_pstn_area_info));
	printf("���ع��ڳ�;������Ϣ\n");
	//read_pstn_area_info("DIM_PSTN_AREA_INFO", "AREA_CODE", "AREA_TYPE");
	read_pstn_area_info(chk.pstn_area_info_table_name, "AREA_CODE", "AREA_TYPE");
	
	printf("�����ƶ��������������Ϣ\n");
	// ȡ�ü�¼��
	//msisdn_num = read_msisdn_info_num("DIM_MSISDN_INFO", "MSISDN_PREFIX");
	msisdn_num = read_msisdn_info_num(chk.msisdn_info_table_name, "MSISDN_PREFIX");
	printf("msisdn_num=[%d]\n", msisdn_num);
	
	// ����ռ�
    m_msisdn_info=(char**)malloc((msisdn_num)*sizeof(*m_msisdn_info));
    *m_msisdn_info=(char*)malloc((msisdn_num)*16*sizeof(**m_msisdn_info));
    for(int i=0; i<(msisdn_num); i++)
    {
        m_msisdn_info[i]=*m_msisdn_info+16*i;
    }        
    
    for(int i=0; i<msisdn_num; i++)
    {
       memset(m_msisdn_info[i], '\0', 16);
    }

	//read_msisdn_info("DIM_MSISDN_INFO", "MSISDN_PREFIX", "AREA_CODE", "AREA_TYPE");
	read_msisdn_info(chk.msisdn_info_table_name, "MSISDN_PREFIX", "AREA_CODE", "AREA_TYPE");

    return 0;
}


// ȡ�ô�����ֻ������ǰ7λ������������ĵ�����Ϣ
// ����ֵ˵�� -1=û�ҵ� ��-1ʱ��Ϊ��������ǰ7λ�ڽṹ��ƥ���ϵ�����λ��
int  find_msisdn_area_info(char *msisdn)
{
    int         iRet = 0;
    int         iRet_DB = 0;

    int         lLeft = 0;
    long        lMiddle = 0;
    int         lRight = msisdn_num - 1;


	while(lLeft <= lRight)
    {
        lMiddle = (lLeft + lRight) / 2;
        //iRet = memcmp(m_msisdn_info[lMiddle], msisdn, strlen(m_msisdn_info[lMiddle]));
        // ȡ���ַ�����ǰ7λ���жԱ�
        iRet = memcmp(m_msisdn_info[lMiddle], msisdn, 7);
        //printf("lMiddle=[%d] iRet=[%d]\n\n", lMiddle, iRet);
		
        if(iRet == 0)
        {
            //return 1;
            return lMiddle;
        }

        if(iRet < 0)
            lLeft = lMiddle + 1;
        else
            lRight = lMiddle - 1;
    }

	return -1;
	
}



// �����ط�������Ϣ
int read_spec_services_info()
{
	char* p_field;
	


	read_spec_services("DIM_SPEC_SERVICES", "ACCESS_NUMBER", access_numbers);
	printf("�ط������б�Ϊ=[%s]\n", access_numbers.c_str());

    return 0;
}



int find_spec_services_info(char *access_number)
{
	char tmp[33];
	
	char *p;
	
	memset(tmp, '\0', sizeof(tmp));
	strcpy(tmp, ",");
	strcat(tmp, access_number);
	strcat(tmp, ",");
	//printf("tmp=[%s]\n", tmp);

	p= strstr(access_numbers.c_str(), tmp);
	
    if(p == NULL)
    {
    	return 0;	
    }
	else
	{
    	return 1;
	}

}



int read_prefix_info()
{
	char* p_field;
	string numbers_prefixs;
	
	int i=0;

	set<string> 			m_prefix_info;
	set<string>::iterator 	m_pos_prefix_info;

	printf("���غ���ǰ׺��Ϣ\n");
	// ȡ�ü�¼��
	//numbers_prefix_info_num = read_numbers_prefix_info_num("DIM_NUMBERS_PREFIX_INFO", "NUMBERS_PREFIX");
	numbers_prefix_info_num = read_numbers_prefix_info_num(chk.numbers_prefix_info_table_name, "NUMBERS_PREFIX");
	//printf("numbers_prefix_info_num=[%d]\n", numbers_prefix_info_num);
	
	// ����ռ�
    m_numbers_prefix_info=(char**)malloc((numbers_prefix_info_num)*sizeof(*m_numbers_prefix_info));
    *m_numbers_prefix_info=(char*)malloc((numbers_prefix_info_num)*11*sizeof(**m_numbers_prefix_info));
    for(int i=0; i<(numbers_prefix_info_num); i++)
    {
        m_numbers_prefix_info[i]=*m_numbers_prefix_info+11*i;
    }        
    
    for(int i=0; i<numbers_prefix_info_num; i++)
    {
       memset(m_numbers_prefix_info[i], '\0', 11);
    }

	//read_numbers_prefix_info("DIM_NUMBERS_PREFIX_INFO", "NUMBERS_PREFIX", numbers_prefixs);
  read_numbers_prefix_info(chk.numbers_prefix_info_table_name, "NUMBERS_PREFIX", numbers_prefixs);
	printf("ǰ׺�б�Ϊ=[%s]\n", numbers_prefixs.c_str());
	
	p_field = strtok((char*)(numbers_prefixs.c_str()), ",");
	while(p_field)
	{
		//printf("p_field=[%s]\n", p_field);
		//����
		m_prefix_info.insert(p_field);

		p_field = strtok(NULL, ",");
	}

	// ��������
	for(m_pos_prefix_info=m_prefix_info.begin(); m_pos_prefix_info!=m_prefix_info.end(); ++m_pos_prefix_info)
    {
        //printf("[%s]\n", (*m_pos_prefix_info).c_str());
        strcpy(m_numbers_prefix_info[i], (*m_pos_prefix_info).c_str());
        
        i++;
    }

    return 0;	
}


int  find_prefix_info(char *numbers)
{
    int iRet = 0;
	int i=8;

	char str_numbers[30], tmp_numbers[30];

	// �����ȴ���8ʱ,��ȡǰ8���ֽڽ���ƥ�����
	memset(str_numbers, '\0', sizeof(str_numbers));
	strcpy(str_numbers, numbers);
    if(strlen(str_numbers) < i)
    {
    	i = strlen(str_numbers);
    }

	while(1)
	{
		// ������С��3ʱ,��Ϊû���ҵ�
    	if(i<3)
    	{
    		return -1;
    	}

    	// ȡ��ÿ�δ��Ƚϵ��ַ���
    	memset(tmp_numbers, '\0', sizeof(tmp_numbers));
		strncpy(tmp_numbers, str_numbers, i);
		//printf("tmp_numbers=[%s]\n", tmp_numbers);

    	int         lLeft = 0;
		long        lMiddle = 0;
		int         lRight = numbers_prefix_info_num - 1;

		while(lLeft <= lRight)
		{
			lMiddle = (lLeft + lRight) / 2;
			iRet = strcmp(m_numbers_prefix_info[lMiddle], tmp_numbers);
			//printf("m_numbers_prefix_info[lMiddle]=[%s]\n", m_numbers_prefix_info[lMiddle]);
			if(iRet == 0)
			{
				return i;
			}

			if(iRet < 0)
			{
				lLeft = lMiddle + 1;
        	}
			else
            {
				lRight = lMiddle - 1;
			}
		}
		
		i--;
    }

	return -1;
	
}

*/
