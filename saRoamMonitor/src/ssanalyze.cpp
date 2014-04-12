/**
* Copyright (c) 2010 AsiaInfo. All Rights Reserved.                     
* Creator: zhoulb  email:zhoulb@asiainfo.com
* Modified log��
*	    1> zhoulb	2010-03-01	Create 
*     2> 
* Description: 
*     ��¼���룬�����Ϻ����û���Ϣ��������ͬ��ͳ�����뱾�ص��û���Ϣ������ʱ������ 
* Input:
*     ����ּ��������ļ�
* Output:
*     �ͻ����������䶯���
*     �����û����
* ������뷶Χ��
*       R0001 -- R1000 
*/

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

//�����ʽ�������������
int field_imsi_num = 0;
int field_msisdn_num = 0;
int field_event_type_num = 0;
int field_time_stamp_num = 0;
int field_duration_num = 0;
int field_lac_id_num = 0;
int field_ci_id_num = 0;
int field_cause_num = 0;
int field_other_party_num = 0;
int field_hlr_num = 0;
int field_vlr_num = 0;	

//���HLR��vlr������
char **hlrList=NULL,**vlrList=NULL;
int hlrCounts =0,vlrCounts = 0;

// ���ӹ��˻�����
pthread_mutex_t filtrate_mutex;
// ���ӳ�ʼ��������
pthread_mutex_t pthread_init_mutex;
// ��־������
pthread_mutex_t pthread_logfile_mutex;

//set<string> 				m_access_number;
//set<string>::iterator 		m_pos_access_number;
string access_numbers;


/*
* ������;��
*     1.���������Ĵ������������������ȡ�̻߳����л�ȡ�����¼���д���
*     2.ͨ���������ȡ�̶߳Ի��廥���������ͻ
*     3.ͨ����ȡ�����ȡ�̷߳��͵��˳��ź��˳�
*/
void *consume( void *arg)
{
	int i,ret,ruleid,rit;
	int len[50];	
	char line[BIG_MAXLINE], line_tmp[BIG_MAXLINE];
	char str_result[BIG_MAXLINE];
	char *word[50];
	char imsi[16];
	char msisdn[30];
	char hlr[16],vlr[16];	
	char errinfo[200];
	int pthread_id;	
	Context rec;
	char str_tmp[2];
	time_t event_time,event_time_begin;
	char str_event_time[20];
	char event_type[10];
	int event_hour = 0;
	char str_event_hour[3];
	int vlrlocal = 0;  //VLR�Ƿ�Ϊ���أ�1Ϊ�ǣ�0Ϊ��
	int hlrlocal = 0;  //HLR�Ƿ�Ϊ���أ�1Ϊ�ǣ�0Ϊ��
	
	FILE	*ftp_tmp;
	/*
		�����쳣�˳�ʱ����tmp�ļ���������ʱ�������������ʱ��ο��ܲ�һ�£�
		������Ҫȡtmp�ļ�����������ʱ��Ϊ�л�ʱ��� 20100408
	*/		
	memset(line_tmp, '\0', sizeof(line_tmp));
				
	for(i=0; i<chk.load_file_num; i++){
		pthread_mutex_lock( &ana.mutex[i]);
		//printf("0001 ana.fname[i]=%s \n",ana.fname[i]);		
		ftp_tmp=fopen(ana.fname[i], "r");	
		if( ftp_tmp != NULL){		 			
			// ȡ���ļ��еĵ�һ����¼
			if(fgets(line_tmp,BIG_MAXLINE,ftp_tmp) != NULL){		
				//printf("line_tmp=%s",line_tmp);	
				if(strlen(line_tmp) > 0){
					//������ʱ�ļ���һ������ʱ���	
					ret=Split(line_tmp, ',', 50, word, len);		
					//��tmp�ļ�ʱ����н�ȡ19λ
					memset(str_event_time, '\0', sizeof(str_event_time));
					strncpy(str_event_time, word[5], 19);
					if(strlen(str_event_time) <=0 ){
					  memset(str_event_time, '\0', sizeof(str_event_time));
						strncpy(str_event_time, word[4], 19);						
					}
					//printf("str_event_time=[%s]\n", str_event_time);		
		
					//ȡ�������¼���ʼʱ���
					event_time = ToTime_t(str_event_time);		
					//����Сʱ�����Ӻ�������
					if(event_time > 0 ) {
						event_time_begin = get_hour_time(event_time);							
  	  			ana.event_time_begin[i] = event_time_begin;
  	  	  } 				
				}
			}
			fclose(ftp_tmp);			
	  }		
		pthread_mutex_unlock( &ana.mutex[i] );
	}

	pthread_id = pthread_self();	
	memset(&rec, '\0', sizeof(rec));	
    
	printf("���������Ĵ����߳̿�ʼ����,�̺߳�:[%d]...\n", pthread_id);
	while(1){
		pthread_mutex_lock(&lb.mutex);
		while( lb.lines <= 0 && exitflag==0 ){		
			pthread_cond_wait(&lb.more, &lb.mutex);
		}

		if(lb.lines <= 0 && exitflag != 0){
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
			
			//������������Ϣ
      ret = BackupContext("roam_context.backup");      
      				
			pthread_cond_broadcast(&lb.more);
			pthread_mutex_unlock(&lb.mutex);
			memset(errinfo,'\0',sizeof(errinfo));
			sprintf(errinfo,"���������Ĵ����߳��˳�,������飡");		   
			printf("%s\n",errinfo);
			write_error_file(chk.err_file_path,"saRoamMonitor","64",2,errinfo);				
			pthread_exit(0);
		}

		memset(line_tmp, '\0', sizeof(line_tmp));
		memset(line, '\0', sizeof(line));
		
		ret = GetLine(&lb, line);
		//printf("consume get line=[%s] \n", line);
		pthread_cond_signal(&lb.less);
		pthread_mutex_unlock(&lb.mutex);

		//��ʼ����������������
		strcpy(line_tmp, line);		
		ret=Split(line_tmp, ',', 50, word, len);		
		//printf("line_tmp=[%s]\n", line_tmp);
		//printf("line=%s", line);
		
		//ȡ��IMSI
		memset(imsi, '\0', sizeof(imsi));
		strcpy(imsi, word[field_imsi_num]);
		LTrim(imsi, ' ');
		RTrim(imsi, ' ');
		//printf("imsi=[%s]\n", imsi);
		
		//ȡ�����к���
		memset(msisdn, '\0', sizeof(msisdn));
		strcpy(msisdn, word[field_msisdn_num]);
		LTrim(msisdn, ' ');
		RTrim(msisdn, ' ');		
		
    //ȡHLR
	  memset(hlr, '\0', sizeof(hlr));
	  strcpy(hlr, word[field_hlr_num]);
	  LTrim(hlr, ' ');
	  RTrim(hlr, ' '); 
    
    //ȡVLR
	  memset(vlr, '\0', sizeof(vlr));
	  strcpy(vlr, word[field_vlr_num]);
	  LTrim(vlr, ' ');
	  RTrim(vlr, ' ');
	
		//��������Ϊ�����¼���8��9 ����������Ҫ�����¼���������
	  memset(event_type, '\0', sizeof(event_type));
	  strcpy(event_type, word[field_event_type_num]);			
	  LTrim(event_type, ' ');
	  RTrim(event_type, ' ');
	  	
	  //ȡ�����ʱ��
	  memset(str_event_time,'\0',sizeof(str_event_time));
	  strncpy(str_event_time,word[field_time_stamp_num],19);
	  event_time = ToTime_t(str_event_time);
	 
		//hlr��vlr��������Ҫ��ǰ�޳�
	  if(0 ==  strlen(hlr) ||  0 ==  strlen(vlr)){
  	 	   continue;
	  }	 		
		
		hlrlocal = vlrlocal = 0 ;
		
		//��HLR VLRͬʱ���������Ϻ�ʱ��Ϊ������·��������ͬʱ��¼�ļ�
		//�жϵ�ǰ��������HLR�Ƿ�Ϊ����
		for(int i=0 ; i < hlrCounts ; i++){
		  if(strcmp(hlrList[i],hlr) == 0){  
		   		hlrlocal = 1;
		   		break;    	 	    
		  }
	  }
	  //�жϵ�ǰ��������VLR�Ƿ�Ϊ����
		for(int j=0 ; j<vlrCounts ; j++){
			if(strcmp(vlrList[j],vlr) == 0){  
			    vlrlocal = 1;
			    break; 	 	  
			}	   
		}
		
		/*if(strcmp(imsi,"460006885000466") == 0){
		    printf("hlr=[%d],[%d]",hlrlocal,vlrlocal);	
		}*/
		//vlrlocal = 1;
		//printf("______hlrlocal=[%d],vlrlocal=[%d]\n",hlrlocal,vlrlocal);
		if( hlrlocal == 1){  //�Ϻ��û���������
		    continue;
		}
		if( hlrlocal == 0 && vlrlocal == 0 ) {  //���Ϻ��û�������vlr�����Ϻ����������־�ļ�����������
        write_other_file(chk.log_file_path,"saRoamMonitor",line); //д��־�ļ�	    
		    continue;	
		}		
	
	  //��ʼ��context
		memset(&rec, '\0', sizeof(rec));	
		memset(str_result, '\0', sizeof(str_result));			
	
		//�õ���	  	
		pthread_mutex_lock(&chk.mutex);		
		
	  memset(str_tmp, '\0', sizeof(str_tmp));
	  strncpy(str_tmp, (msisdn)+10, 1);
	  ruleid = (atoi(str_tmp))%chk.load_file_num;	
		//printf("event_begin_time=[%d]\n",ana.event_time_begin[ruleid]);
		
		memset(str_event_time,'\0',sizeof(str_event_time));
		strncpy(str_event_time,word[field_time_stamp_num],19);
		//memset(str_event_hour,'\0',sizeof(str_event_hour));
		//strncpy(str_event_hour,word[field_time_stamp_num]+11,2);				
		//event_hour = atoi(str_event_hour);
		//printf("get_event_time=[%s]\n",str_event_time);	  	
	  event_time = ToTime_t(str_event_time);
	  event_time_begin = get_hour_time(event_time);

    //��������ÿСʱ����һ���ļ�
    //printf("event_time_begin=[%d],ana.event_time_begin[ruleid]=[%d]\n",event_time_begin,ana.event_time_begin[ruleid]);
    if (event_time_begin != ana.event_time_begin[ruleid] ){
  	  if(ana.event_time_begin[ruleid] == -1){
  	     ana.event_time_begin[ruleid] = event_time_begin; 	
  	  }else{ 			 		
		 		//��������Ϣ���������  
		 		ret = update_user_resident_time();		 			
		 		//�����ļ�		 		
		 		ret = load_timer();		 		
		 		//��ʱ���
				ana.event_time_begin[ruleid] = event_time_begin;
				
				//�����������������ʱ�䣬��ͣ�ȴ�����������
				//init_timer(event_hour);					
				//printf("�л��ļ����� ana.event_time_begin[%d]=[%d]\n", ruleid,ana.event_time_begin[ruleid]);	
		  }	  
	  }
		
		ret=GetFromContext(imsi, &rec);		
		if( ret == -1 ) {
			  //����û���������ڴ治������Ϊ�뿪����ô������
			  if(hlrlocal == 0  && strcmp(event_type,"9") == 0){
						pthread_mutex_unlock(&chk.mutex);
						continue;	
			  }
			  
			  if(chk.imsi_msisdn_flag == 2) {
						//���������в��ҿ���	
						if(chk.context_capacity <= chk.context_capacity_used){
				        memset(errinfo,'\0',sizeof(errinfo));
			          sprintf(errinfo,"�����û�[%s]���������ĵ�����������ÿͻ���Ϣ���������ע��", line);		   
			          write_error_file(chk.err_file_path,"saRoamMonitor","51",2,errinfo);								
								pthread_mutex_unlock(&chk.mutex);
								continue;							
						}			  	
				    InsertContext(imsi,msisdn);						
						GetFromContext(imsi, &rec);				  	
			  }else{
						if((chk.imsi_msisdn_flag == 0) || ((strlen(msisdn) == 0 ) && (chk.imsi_msisdn_flag == 1))){
								pthread_mutex_unlock(&chk.mutex);
								continue;
						}
				}
		} 		
		update_user_info(word, &rec, str_result,ret,hlrlocal,vlrlocal);
		pthread_mutex_unlock(&chk.mutex);		   
	}
}

/**
*   ������;��
*       1. �޸����οͻ�����������Ϣ
*       2. ������ͻ�����ʱ������������������Ϣ
**/
int update_user_info(char *word[], Context *rec, char *str_result_tmp,int isexist,int hlrlocal,int vlrlocal)
{
	char imsi[16];
	char msisdn[16];
	time_t event_time,event_time_begin;
	char str_event_time[20],str_event_second[8];
	char hlr[16];
	char vlr[16];
	char event_type[10];	
	int ret = 1;

	time_t curr_system_time;
	char str_curr_system_time[20];
	struct tm *tp;	
  int ruleid;
	char str_tmp[2];

	int user_type = 0;
			
	/*memset(str_event_time, '\0', sizeof(str_event_time));
	tp = localtime(&event_time);
	sprintf(str_event_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);*/
 
  //ȡIMSI
	memset(imsi, '\0', sizeof(imsi));
	strcpy(imsi, word[field_imsi_num]);
	LTrim(imsi, ' ');
	RTrim(imsi, ' ');
	
  //ȡHLR
	memset(hlr, '\0', sizeof(hlr));
	strcpy(hlr, word[field_hlr_num]);
	LTrim(hlr, ' ');
	RTrim(hlr, ' '); 
  
  //ȡVLR
	memset(vlr, '\0', sizeof(vlr));
	strcpy(vlr, word[field_vlr_num]);
	LTrim(vlr, ' ');
	RTrim(vlr, ' ');
	
	//��������Ϊ�����¼���8��9 ����������Ҫ�����¼���������
	memset(event_type, '\0', sizeof(event_type));
	strcpy(event_type, word[field_event_type_num]);			
	LTrim(event_type, ' ');
	RTrim(event_type, ' ');

	//ȡ�����ʱ��
	memset(str_event_time,'\0',sizeof(str_event_time));
	strncpy(str_event_time,word[field_time_stamp_num],19);
	event_time = ToTime_t(str_event_time);
	//printf("event_time=[%d],,[%s],,[%s]\n",event_time,str_event_time,word[field_time_stamp_num]);
		
	// ȡ��ϵͳ��ǰʱ��
	/*memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
	time(&curr_system_time);
	tp = localtime(&curr_system_time);
	sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_curr_system_time=[%s]\n", str_curr_system_time);*/

  //--------------------------------------------------------------------------
	//----------------��ʼ���¿ͻ�����������Ϣ----------------------------------
	//--------------------------------------------------------------------------	
	//printf("hlrlocal=[%d],,[%s]\n",hlrlocal,event_type);	  
  if(hlrlocal == 0){  //����û�  	
  	if(strcmp(event_type,"8") == 0){  //����û������¼�	 
  		  if(isexist == -1 || rec->user_type == 0)  {   //�����Ĳ����ڣ�������һ��
  	     rec->user_type = 1 ;
  	     //����ʱ��  	 
  	 	   rec->come_time = event_time;
  	 	   //����ʱ�� ΢�� 	                                  
         memset(rec->str_come_time, '\0', sizeof(rec->str_come_time));  	 
  	     strcpy(rec->str_come_time,word[field_time_stamp_num]);    
  	     //�û�HLR                         	  	            	     
         memset(rec->hlr, '\0', sizeof(rec->hlr));                        
  	     strcpy(rec->hlr,hlr);
  	     // ��ǰVLR
  	     memset(rec->current_vlr,'\0',sizeof(rec->current_vlr));
  	     strcpy(rec->current_vlr,vlr);
  	     //��ǰ����ʱ��
  	     rec->current_update_time = event_time; 
  	     memset(rec->str_current_update_time,'\0',sizeof(rec->str_current_update_time));
  	     strcpy(rec->str_current_update_time,word[field_time_stamp_num]);	      	
  	   }else{
  	   	 memset(rec->latest_vlr,'\0',sizeof(rec->latest_vlr));
  	   	 strcpy(rec->latest_vlr,rec->current_vlr);
  	   	 rec->latest_update_time = rec->current_update_time;
  	   	 memset(rec->str_latest_update_time,'\0',sizeof(rec->str_latest_update_time));
  	   	 strcpy(rec->str_latest_update_time,rec->str_current_update_time);
  	   	 rec->latest_delete_time = rec->current_delete_time;
  	   	 memset(rec->str_latest_delete_time,'\0',sizeof(rec->str_latest_delete_time));
  	   	 strcpy(rec->str_latest_delete_time,rec->str_current_delete_time);
  	   	 memset(rec->current_vlr,'\0',sizeof(rec->current_vlr));
  	   	 strcpy(rec->current_vlr,vlr);
  	   	 rec->current_update_time = event_time; 	
  	     memset(rec->str_current_update_time,'\0',sizeof(rec->str_current_update_time));
  	     strcpy(rec->str_current_update_time,word[field_time_stamp_num]);
  	     rec->current_delete_time = 0;
  	     memset(rec->str_current_delete_time,'\0',sizeof(rec->str_current_delete_time));	
  	   }
  	   if(rec->latest_delete_time > 0 
  	   	  && abs(rec->current_update_time-rec->latest_delete_time) > chk.signal_roam_judge_change ) {
  	         rec->leave_time = rec->latest_delete_time;
   	         memset(rec->str_leave_time,'\0',sizeof(rec->str_leave_time));
   	         strcpy(rec->str_leave_time,rec->str_latest_delete_time);	      
   	         rec->resident_time = rec->latest_delete_time - rec->come_time; 
   	         memset(rec->vlr,'\0',sizeof(rec->vlr));
   	         strcpy(rec->vlr,rec->latest_vlr);
   	          	          	                   	     	  	
	           memset(str_tmp, '\0', sizeof(str_tmp));
	           strncpy(str_tmp, (rec->msisdn)+10, 1);
	           ruleid = (atoi(str_tmp))%chk.load_file_num;		           	 							
		         //�ӹ��˻�����
		         pthread_mutex_lock(&filtrate_mutex);
		         //���������ļ���
		         GetResultStr(rec,0,str_result_tmp);
		         WriteResult(ruleid, str_result_tmp);		
		         //printf("output:[%s]\n",str_result_tmp);	
		         pthread_mutex_unlock(&filtrate_mutex); 
		         
		         //������������Ϣ���
		         rec->come_time = rec->current_update_time;
		         memset(rec->str_come_time,'\0',sizeof(rec->str_come_time));
		         strcpy(rec->str_come_time,rec->str_current_update_time);
		         memset(rec->vlr,'\0',sizeof(rec->vlr));
		         rec->leave_time = 0 ;
		         memset(rec->str_leave_time,'\0',sizeof(rec->str_leave_time));
		         rec->resident_time = 0;		
		         rec->current_delete_time =0; 
		         memset(rec->str_current_delete_time,'\0',sizeof(rec->str_current_delete_time));
		         memset(rec->latest_vlr,'\0',sizeof(rec->latest_vlr));
		         rec->latest_update_time = 0;
		         memset(rec->str_latest_update_time,'\0',sizeof(rec->str_latest_update_time));
		         rec->latest_delete_time = 0;
		         memset(rec->str_latest_delete_time,'\0',sizeof(rec->str_latest_delete_time));         	
  	     }
  	}else{                        //��ؿͻ����� ,����������ͬʱ��Ҫ�仯�����
  		   if(rec->user_type == 0) {  // ���¼�����Ϊ9ʱ������ʱ���ڴ�Ϊ����״̬���򲻽��д���
  		         return ret;	
  		   }
   	   	 //printf("****************3=[%s],[%s],[%s]\n",vlr,rec->current_vlr,rec->latest_vlr);  	     		   
  		   if(strcmp(vlr,rec->current_vlr) == 0 && strcmp(vlr,rec->latest_vlr) == 0){
  		      rec->current_delete_time = event_time;
  		      memset(rec->str_current_delete_time,'\0',sizeof(rec->str_current_delete_time));
  		      strcpy(rec->str_current_delete_time,word[field_time_stamp_num]);  		   
  		   }else if(strcmp(vlr,rec->current_vlr) == 0){
  		      rec->current_delete_time = event_time;
  		      memset(rec->str_current_delete_time,'\0',sizeof(rec->str_current_delete_time));
  		      strcpy(rec->str_current_delete_time,word[field_time_stamp_num]);
  		   }else if(strcmp(vlr,rec->latest_vlr) == 0){
  		      rec->latest_delete_time = event_time;
  		      memset(rec->str_latest_delete_time,'\0',sizeof(rec->str_latest_delete_time));
  		      strcpy(rec->str_latest_delete_time,word[field_time_stamp_num]);	  		      	
  		   }else{
  		      return ret;	
  		   } 	 	
  	 	}	
  	}
	
	  //put��������
	  PutToContext(imsi, rec);	
	return ret;	
}


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



// imsi��msidsnת��
// ͨ��imsiת�����й��ƶ�����ǰ׺
// ת�������λ��134-139,150-152,157-159,187,188 �����Ŷξ�����ת��
char* imsi_msisdn_trans(char* imsi)
{
	char* buffer = NULL;
	//char* ret_buffer = NULL;
	char ret_buffer[7];
	char* buffer_tmp = NULL;
	char tmp[7];
	
	int ret;

	memset(ret_buffer, '\0', 7);

	if( memcmp(imsi,"46000",5) == 0)
	{
		//135-139
		buffer_tmp = imsi+8;
		strncat(ret_buffer, buffer_tmp, 1);
		ret = atol(ret_buffer);
		memset(ret_buffer, '\0', 7);
		if(ret >= 5)
		{
			buffer_tmp = imsi+5;
			strcat(ret_buffer, "13");
			sprintf(tmp,"%d",ret);
			strcat(ret_buffer, tmp);
			strcat(ret_buffer, "0");
			strncat(ret_buffer, buffer_tmp, 3);			
		}
		else
		{
			buffer_tmp = imsi+5;
			strcat(ret_buffer, "13");
			ret = ret + 5; 
			sprintf(tmp,"%d",ret);
			strcat(ret_buffer, tmp);
			buffer_tmp = imsi+9;
			strncat(ret_buffer, buffer_tmp, 1);	
			buffer_tmp = imsi+5;
			strncat(ret_buffer, buffer_tmp, 3);			
		}
	}
	else if( memcmp(imsi,"460020",6) == 0)
	{
		//134
		buffer_tmp = imsi+6;
		strcat(ret_buffer, "134");
		strncat(ret_buffer, buffer_tmp, 4);
	}		
	else if(memcmp(imsi,"460077",6) == 0)
	{
		//157
		buffer_tmp = imsi+6;
		strcat(ret_buffer, "157");
		strncat(ret_buffer, buffer_tmp, 4);
		//sprintf(ret_buffer, "%04s", buffer_tmp);
	}	
	else if( memcmp(imsi,"460078",6) == 0)
	{
		//188
		buffer_tmp = imsi+6;
		strcat(ret_buffer, "188");
		strncat(ret_buffer, buffer_tmp, 4);
	}
	else if( memcmp(imsi,"460027",6) == 0)
	{
		//187
		buffer_tmp = imsi+6;
		strcat(ret_buffer, "187");
		strncat(ret_buffer, buffer_tmp, 4);
	}	
	else if( (memcmp(imsi,"460021",6) == 0) || (memcmp(imsi,"460022",6) == 0) || (memcmp(imsi,"460023",6) == 0) 
		       || (memcmp(imsi,"460028",6) == 0) || (memcmp(imsi,"460029",6) == 0))
	{
		//150~152��158/159
		if( memcmp(imsi,"460023",6) == 0)
		{
			buffer_tmp = imsi+6;
			strcat(ret_buffer, "150");
			strncat(ret_buffer, buffer_tmp, 4);			
		}
		else
		{
			buffer_tmp = imsi+5;
			strcat(ret_buffer, "15");
			strncat(ret_buffer, buffer_tmp, 5);			
		}		
	}					

	//printf("ret_buffer=[%s]\n", ret_buffer);
	//sprintf(buffer,"%s",ret_buffer);
	buffer = ret_buffer;
	//memset(ret_buffer, '\0', 7);
	return buffer;
	//return ret_buffer;
}

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
	
	
/*	
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
*/

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

	//***********************************************************************************
	//*********************** ȡ�öԶ˺�������������Ϣ��ʼ ****************************
	//***********************************************************************************
	

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
	//***********************************************************************************
	//*********************** ȡ�öԶ˺�������������Ϣ���� ****************************
	//***********************************************************************************

	// ���Զ˺����ҵ���������Ϣʱ
	if(opp_area_flag == 1)
	{
		// calling_other_party_area��called_other_party_area��ʽ��
		// ��ʽ���������ͣ�1λ��@���Ŵ��루����0��ȥ����2-3λ��
		// ������2@551 ��2-ʡ�� 3-ʡ�� 4-���⣩
/*
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
*/		
	}
	
	//printf("in update_other_party_area,opp_area_info=[%s],opp_num_cleanout=[%s] \n", opp_area_info,opp_num_cleanout);
}


// time_flag=1ʱ���뿪ʱ��ȡϵͳ��ǰʱ��
// time_flag=0ʱ���뿪ʱ��ȡrec�ж�Ӧ�ֶε�ʱ��
int GetResultStr(Context *rec, int time_flag, char *str_result_tmp)
{
	char line[BIG_MAXLINE];
	char tmp[20];
	struct tm *tp;

	// ȡ��ϵͳ��ǰʱ��
	/*time_t curr_system_time;
	char str_curr_system_time[20];
	memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
	time(&curr_system_time);
	tp = localtime(&curr_system_time);
	sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_curr_system_time=[%s]\n", str_curr_system_time);*/
  
  //��ʼ�������¼�ַ���
	memset(line, '\0', sizeof(line));
  //imsi
  strcpy(line, rec->imsi);
	strcat(line,",");		

  //msisdn
  strcat(line, rec->msisdn);
	strcat(line,",");
    	
  //HLR
	strcat(line, rec->hlr);
	strcat(line,",");

	//VLR
	strcat(line, rec->current_vlr);
	strcat(line,",");			
  	  	
	//����ʱ�䴦��
	strcat(line, rec->str_come_time);
	strcat(line,",");		
		
	//�뿪ʱ�䴦��
	strcat(line, rec->str_leave_time);
	strcat(line,",");		
		
	//ͣ��ʱ�������ӣ�			
	sprintf(tmp,"%d",rec->resident_time);
	strcat(line, tmp); 	 			
	
	//������з�
	strcat(line, "\n");
	strcpy(str_result_tmp, line);
	return 1;
}


int WriteResult(int ruleid, char *src)
{
	char *dest;
	char tmp[500];
	size_t	left,from;
	int ret;

	//�߳�ָ��Ļ�����׵�ַ
	dest=ana.fbuf+ruleid*FBUFFSIZE;	
	
	pthread_mutex_lock( &ana.mutex[ruleid]);
	//printf("in WriteResult ok before if( ana.timeout[ruleid] == 1 )");
	if( ana.timeout[ruleid] == 1 ) {
		ana.timeout[ruleid]=0;
		//printf("ana.counts[ruleid]=[%d] ana.num[ruleid]=[%d]\n", ana.counts[ruleid], ana.num[ruleid]);
		if( ana.counts[ruleid] > 0 ) {
			// ��timeoutʱ�䵽�������滹û��д������Ϣ����Ҫ������ļ���������
			if(ana.fd[ruleid]<=0){
				ana.fd[ruleid] = open(ana.fname[ruleid], O_APPEND|O_WRONLY|O_CREAT, 0644);
			}
			//printf("1111 ana.num[ruleid]=[%d] dest=[%s]\n", ana.num[ruleid], dest);
			WriteN(ana.fd[ruleid], dest, ana.num[ruleid]);
			//WriteN_wld(ana.fd[ruleid], dest, ana.num[ruleid]);
			close(ana.fd[ruleid]);
     }
      //�ڴ�����������˳�ʱ�������ļ���
      // ȡ���¼���ʼ��ʱ���
			tm *event_time_begin;
			char str_event_time_begin[20];
			memset(str_event_time_begin, '\0', sizeof(str_event_time_begin));		
			event_time_begin = get_str_time(str_event_time_begin,ana.event_time_begin[ruleid]);
			//printf("str_event_time_begin=[%s]\n", str_event_time_begin);

			memset(tmp, '\0', sizeof(tmp));
			char fname_tmp[200];
			memset(fname_tmp, '\0', sizeof(fname_tmp));
			strncpy(fname_tmp, ana.fname[ruleid], strlen(ana.fname[ruleid])-4);
			//�����ϵͳʱ�������Ϊ����¼���ʼ��ʱ���
			sprintf(tmp, "%s_%s", fname_tmp, str_event_time_begin);
			//sprintf(tmp, "%s_%s", fname_tmp, str_sys_time);
			//printf("����ļ���Ϊ=[%s]\n", tmp);
			rename(ana.fname[ruleid], tmp);
			
			/*bzero(dest, FBUFFSIZE);*/
			memset(dest, '\0', FBUFFSIZE);
			ana.fd[ruleid] = Open(ana.fname[ruleid], O_APPEND|O_WRONLY|O_CREAT);
			ana.num[ruleid]=0;
			ana.counts[ruleid]=0;		
	}else{
	    left=strlen(src);
	    from=0;
	    ana.counts[ruleid] ++;          
	    while( left>0 ) {
	    	if(left+ana.num[ruleid] <= FBUFFSIZE) {
	    		/*bcopy(src+from, dest+ana.num[ruleid], left);20090326*/
	    		memcpy(dest+ana.num[ruleid],src+from, left);
	    		ana.num[ruleid] += left;
	    		left = 0;
	    	}else {
	    		/*bcopy(src+from, dest+ana.num[ruleid], FBUFFSIZE-ana.num[ruleid]); 20090326*/
	    		memcpy(dest+ana.num[ruleid],src+from, FBUFFSIZE-ana.num[ruleid]);
	    		left -= (FBUFFSIZE- ana.num[ruleid]);
	    		from += (FBUFFSIZE- ana.num[ruleid]);
      
	    		if(ana.fd[ruleid]>0) WriteN(ana.fd[ruleid], dest, FBUFFSIZE);
	    		else{
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
	}
	//�ͷ���
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

	/*printf("1  msisdn:%s\n", rec.msisdn);
	printf("2  imsi:%s\n", imsi);
	printf("3  last_cell:%s\n",rec.last_cell);
	printf("4  mobile_open_counts:%c\n",rec.mobile_open_counts);
	printf("5  mobile_close_counts:%c\n",rec.mobile_close_counts);
		
	printf("6  smo_sms_counts:%d\n",rec.smo_sms_counts);
	printf("7  calling_call_counts:%d\n",rec.calling_call_counts);
	printf("8  smt_sms_counts:%d\n",rec.smt_sms_counts);
	printf("9  called_call_counts:%d\n",rec.called_call_counts);
	printf("10 mo_mms_counts:%d\n",rec.mo_mms_counts);
	printf("11  mt_mms_counts:%d\n",rec.mt_mms_counts);
	printf("12  smo_cm_counts:%d\n",rec.smo_cm_counts);
		
	tp = localtime( &rec.come_time);
	printf("13 come_time:%4d.%02d.%02d %02d:%02d:%02d\n",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);

	tp = localtime( &rec.leave_time);
	printf("14 leave_time:%4d.%02d.%02d %02d:%02d:%02d\n",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);

	tp = localtime( &rec.ler_time);
	printf("15 ler_time:%4d.%02d.%02d %02d:%02d:%02d\n",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	
	printf("16 resident_time:%s\n",rec.resident_time);
	printf("17 last_action_type:%d\n",rec.last_action_type);*/
}

int main (int argc, char *argv[])
{
	int i;
	float size;
	pthread_t	tid_produce,tid_monitor;
	pthread_t	tid_backup,tid_init,tid_load;
	pthread_t	*tid_consume;
	pthread_t	tid_resident;
	pthread_attr_t attr;

	Config *cfg;
	
	int ret;
  char buff[300];
  char filename[100];
  char sqlstring[100];
	
	int fd_map;
	char initfile[100];
	memset(initfile,'\0',sizeof(initfile));

	//���ճ�ʼ���ļ�
	if(argc > 2 ){
		printf("saRoamMonitor paramter error!\n");
		exit(0);
	}else if(argc == 2){
	  strcpy(initfile,argv[1]);
	  fd_map=open(initfile, O_RDONLY);	
	  if(fd_map == -1){
	  	printf("init file is not found!\n");
	  	close(fd_map);
	  	exit(0);
	  }
	  close(fd_map);	  	
	}
	
	cfg = (Config *)Malloc(sizeof(Config));
	ReadConfig("../etc/saRoamMonitor.conf", cfg);
		
	PrintCfg(cfg);
	
	connect_db(cfg->db_name, cfg->db_user, cfg->db_passwd);	

	chk.hash_tune=cfg->hash_tune;
	chk.analyze_thread_num=cfg->analyze_thread_num;
	chk.load_file_num=cfg->load_file_num;
	chk.direct_receive=cfg->direct_receive;
	strcpy(chk.table_name, cfg->table_name);
	strcpy(chk.select_cond,cfg->select_cond);
	chk.init_context_hour=cfg->init_context_hour;
	chk.init_context_min=cfg->init_context_min;
	chk.backup_context_interval=cfg->backup_context_interval;
	strcpy(chk.physical_area_table_name, cfg->physical_area_table_name);
	strcpy(chk.physical_area_table_cel, cfg->physical_area_table_cel);
	chk.resident_time_raft=cfg->resident_time_raft;
	chk.resident_time_interval=cfg->resident_time_interval;	
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
	strcpy(chk.mobile_prefix_table_name, cfg->mobile_prefix_table_name);	
	chk.signal_sort_flag=cfg->signal_sort_flag;
	chk.signal_sort_capacity=cfg->signal_sort_capacity;
	chk.signal_sort_interval=cfg->signal_sort_interval;	
	strcpy(chk.load_file_prefix, cfg->load_file_prefix);
	strcpy(chk.log_file_path, cfg->log_file_path);	
	strcpy(chk.err_file_path, cfg->err_file_path);
	strcpy(chk.pros_file_path, cfg->pros_file_path);
	strcpy(chk.hlr_table_name, cfg->hlr_table_name);
	strcpy(chk.hlr_select_cond, cfg->hlr_select_cond);
	strcpy(chk.vlr_table_name, cfg->vlr_table_name);
	strcpy(chk.vlr_select_cond, cfg->vlr_select_cond);	
	strcpy(chk.roam_table_name, cfg->roam_table_name);
	strcpy(chk.roam_select_cond, cfg->roam_select_cond);
	strcpy(chk.host_code, cfg->host_code);	
	strcpy(chk.entity_type_code, cfg->entity_type_code);	
	strcpy(chk.entity_sub_code, cfg->entity_sub_code);	
	chk.signal_check_interval=cfg->signal_check_interval;	
	chk.signal_roam_judge_change=cfg->signal_roam_judge_change;
	chk.signal_roam_judge_timing=cfg->signal_roam_judge_timing;

	//��ʼ�������Ĵ�С
	chk.context_capacity = cfg->context_capacity * 1000000 ;			
	free(cfg);
						 		
	time_t begin_time, end_time;
	char str_begin_time[20], str_end_time[20];
	memset(str_begin_time, '\0', sizeof(str_begin_time));
	begin_time = get_system_time(str_begin_time);
	printf("Memory of the Context allocate begin,begin time=[%s]...\n", str_begin_time);
  
	//�����Ŀռ����
	context = (BCDContext *)Malloc(sizeof(BCDContext)*chk.context_capacity);   
  if(context == NULL){	
  	printf("Not Enough Memory in context !\n");
  	exit(1);
  }
 	 			
	//�������ռ�������ʼ��
	Index = (BCDIndex *)Malloc(sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune));
	if(!Index){	
  	printf("Not Enough Memory for Index !\n");
  }
  
	for(i=0; i<chk.context_capacity-chk.hash_tune; i++){
		Index[i].offset=Index[i].redirect= -1;
	}
	
  chk.redirect_capacity = 0;
  chk.context_capacity_used = 0; 
  //��ʼ������1���ض���ռ�
  //redirect = (BCDIndex *)Malloc(sizeof(BCDIndex)*1);
  redirect = (BCDIndex *)Malloc(sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune)); 
	for(i=0; i<chk.context_capacity-chk.hash_tune; i++){
		redirect[i].offset=redirect[i].redirect= -1;
	}


	memset(str_end_time, '\0', sizeof(str_end_time));
	end_time = get_system_time(str_end_time);
	printf("Memory of the context allocate and initialize finish! end time=[%s]\n\n", str_end_time);
  
	printf("View memory size of the context begin...\n");
	printf("sizeof(BCDContext) is %dB\n", sizeof(BCDContext));
	printf("sizeof(BCDIndex) is %dB.\n\n", sizeof(BCDIndex));
  
	printf("subscribers:%d\n", chk.context_capacity);
	printf("conflict_subscribers:%d\n\n", chk.redirect_capacity);
  
	size = sizeof(BCDContext)*chk.context_capacity;
	printf("Context size:%.2f MB\n", (double)size/1048576);
  
	size = sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune);
	printf("Index size:%.2f MB\n", (double)size/1048576);
  
	size=sizeof(BCDIndex)*chk.redirect_capacity;
	printf("Reindex size:%.2f MB\n", (double)size/1048576);
	printf("View memory size of the context end...\n");
 		
 	//���������û���Ϣ��
  //ret = export_roam_file();
	if(strlen(initfile) > 0){
		memset(str_begin_time, '\0', sizeof(str_begin_time));
		begin_time = get_system_time(str_begin_time);
		printf("���������û���Ϣ�������Ŀ�ʼ��str_begin_time=[%s]...\n", str_begin_time);	
		InitContext(initfile);		
		memset(str_end_time, '\0', sizeof(str_end_time));
		end_time = get_system_time(str_end_time);
		printf("���������û���Ϣ�������Ľ�����end_time=[%s]\n\n", str_end_time);
	}
	
	//��ʼ���Ϻ�HLR��Ϣ
	ret = read_hlr_list();
	//��ʼ���Ϻ�VLR��Ϣ
	ret = read_vlr_list();	
		 				 				 				
	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
	
	ana.fbuf = (char *)Malloc(chk.load_file_num * FBUFFSIZE);
	for(i=0; i<chk.load_file_num; i++) {
		pthread_mutex_init(&ana.mutex[i], NULL);
		sprintf(ana.fname[i], "%s%02d.tmp", chk.load_file_prefix, i);
		ana.num[i]=0;
		ana.counts[i]=0;
		ana.fd[i]=-1;
		ana.timeout[i]=-1;
		strcpy(ana.tabname[i], "mtl_ler_user_physical");
		ana.event_time_begin[i] = -1 ;
	}

	pthread_mutex_init(&pthread_init_mutex, NULL);
	pthread_mutex_init(&filtrate_mutex, NULL);
	pthread_mutex_init(&pthread_logfile_mutex,NULL);
  
	//��ȡ�������ӳ��
	read_decode_info();

  //���������������,д�����ļ�
  char moudleName[250] ;
  memset(moudleName,'\0',sizeof(moudleName));
  sprintf(moudleName,"%ssaRoamMonitor.proc",chk.pros_file_path);
  write_heart_file(moudleName);
  
  //��ȡ����������û��������ļ�
	PthreadCreate(&tid_produce, &attr, produce_fr_ftp, NULL); 

	//��consume���ɵ��ļ�����
	//PthreadCreate(&tid_monitor, NULL, load_timer, NULL);
	
	// ����ͣ�������� ͣ��������ֵ����߳�
	//PthreadCreate(&tid_resident, NULL, resident_timer, NULL);

	// �����澯��־����
	PthreadCreate(&tid_backup, NULL, backup_timer, NULL);

	//�������ڳ�ʼ���߳�
	PthreadCreate(&tid_init, NULL, init_timer, NULL);

	// ���������Ĵ����߳�
	tid_consume=(pthread_t*)Malloc(chk.analyze_thread_num*sizeof(pthread_t));
	for(i=0; i<chk.analyze_thread_num; i++) {
		PthreadCreate(tid_consume+i, &attr, consume, NULL);
	}
			
	//�ȴ��ɼ��̣߳������Ĵ����߳̽���
	//��ʼ���̣߳�����̲߳��ȴ������
	pthread_join(tid_produce, NULL);
	//pthread_join(tid_backup, NULL);
	//pthread_join(tid_monitor, NULL);
	//pthread_join(tid_resident, NULL);
	//pthread_join(tid_init, NULL);
	
	for(i=0; i<chk.analyze_thread_num; i++){
		pthread_join( *(tid_consume+i), NULL);
	}
	
	printf("��ʼ׼���ͷ��ڴ�ռ�...");
	if(ana.fbuf != NULL) free(ana.fbuf);
	if(tid_consume != NULL) free(tid_consume);
	if(context != NULL) free(context);
	if(Index != NULL) free(Index);
	if(redirect != NULL) free(redirect);
	if(vlrList != NULL) free(vlrList);
	if(hlrList != NULL) free(hlrList);

	close_db();
	
	char errinfo[200];
	memset(errinfo,'\0',sizeof(errinfo));
	sprintf(errinfo,"���������Ĵ�������˳�,������飡");		
	printf("%s\n",errinfo);   
	write_error_file(chk.err_file_path,"saRoamMonitor","61",2,errinfo);	
	exit(0);
}


int read_conflict_file(char *map_file_name)
{
	int pos;
	int ci,rj;
	int imsino;
	char st2[256];

	int curr_i=0; 

	char msisdn[16];
	char imsi[16];

	int	fd_map;
	char line[40];
	FileBuff fb_map;
	char buff_map[300];
	
	int ret;
	char *word[50];
	
	fb_map.num=0;
	fb_map.from=0;
	int num=1;
	
	int len[50];
	
	ci=rj=0;
	
	// �����ļ��е�ÿ��ӳ������
	fd_map=open(map_file_name, O_RDONLY);
	
	//printf("map_file_name=%s\n",map_file_name);
			
	while(num>0)
	{
		// ȡ���ļ��е�ÿ����¼
		num = ReadLine(fd_map, &fb_map, line, MAXLINE);	// ��num==0ʱ����ʾ�ѵ����ļ�β�����޿ɶ�ȡ������

    //printf("curr_i=%d, num=%d\n",curr_i,num);
		
		if( num > 0 ) 
		{
			//continue;
			memset(word, '\0', sizeof(word));						
			ret=Split(line, ',', 50, word, len);
			
			memset(imsi, '\0', sizeof(imsi));
			strcpy(imsi, word[0]);
			LTrim(imsi, ' ');
			RTrim(imsi, ' ');
			
			//printf("imsi=%s\n",imsi);
			
			imsino = atoi(imsi+6);
			pos = imsino % (chk.context_capacity-chk.hash_tune);
    	
			if( Index[pos].offset == -1) Index[pos].offset = ci;
			else {
				if( Index[pos].redirect == -1) Index[pos].redirect = rj;
				rj++;
			}
			ci++;
    	
    		
    	if(curr_i%100000 == 0)
			{
				printf("��ʼ�� curr_i=[%d]��\n", curr_i);
			}
							
			curr_i++;
			//printf("after curr_i++; \n");
		
		}
	}

	close(fd_map);


	return rj;
}


int read_context_file(char *map_file_name)
{
	int curr_i=0; 
	char str_event_time[20];
	char imsi_cond[16],msisdn_cond[16];
	time_t come_time;
  Context rec;		
	int	fd_map;
	char line[MAXLINE];
	FileBuff fb_map;
	int ret;
	char *word[50];	
	int len[50];	
  char errinfo[100];
	fb_map.num=0;
	fb_map.from=0;
	int num=1;			
	char str_come_time[27];	
	
	//�����ļ��е�ÿ��ӳ������
	fd_map=open(map_file_name, O_RDONLY);
	while(num>0){
		// ȡ���ļ��е�ÿ����¼
		num = ReadLine(fd_map, &fb_map, line, MAXLINE);	// ��num==0ʱ����ʾ�ѵ����ļ�β�����޿ɶ�ȡ������		
		if( num > 0 ) {
			 //printf("___read_line=[%s]\n",line);	   
			 memset(&rec, '\0', sizeof(rec));	
			 memset(word, '\0', sizeof(word));						
			 ret=Split(line, ',', 50, word, len);
		   
			 memset(imsi_cond, '\0', sizeof(imsi_cond));
			 strcpy(imsi_cond, word[0]);
  	  		 
			 memset(msisdn_cond, '\0', sizeof(msisdn_cond));
			 strcpy(msisdn_cond, word[1]);  	
  	   //printf("msisdn_cond=[%s]\n",word[1]);								
       
      ret=GetFromContext(imsi_cond, &rec);
      if(ret == -1 ){
			   if(chk.context_capacity <= chk.context_capacity_used){
				    memset(errinfo,'\0',sizeof(errinfo));
			      sprintf(errinfo,"�����û�[%s]���������ĵ�����������ÿͻ���Ϣ���������ע��", line);		   
			      write_error_file(chk.err_file_path,"saRoamMonitor","51",2,errinfo);								
					  continue;							
			   }											
    	   //���뵽������   		
    	   InsertContext(imsi_cond,msisdn_cond);	
    	   //����������								
			   memset(&rec, '\0', sizeof(rec));

  	     rec.come_time = atoi(word[2]);
  	     rec.leave_time = atoi(word[3]);  
  	     rec.resident_time = atoi(word[6]);
         memset(rec.str_come_time, '\0', sizeof(rec.str_come_time));
  	     strcpy(rec.str_come_time,word[4]);
         memset(rec.str_leave_time, '\0', sizeof(rec.str_leave_time));
  	     strcpy(rec.str_leave_time,word[5]); 	     

         memset(rec.hlr, '\0', sizeof(rec.hlr));  	  
  	     strcpy(rec.hlr,word[7]);	 
         memset(rec.vlr, '\0', sizeof(rec.vlr));  	  
  	     strcpy(rec.vlr,word[8]);	
  	     rec.user_type = atoi(word[9]) ; 
         memset(rec.current_vlr, '\0', sizeof(rec.current_vlr));
  	     strcpy(rec.current_vlr,word[10]);
  	     rec.current_update_time = atoi(word[11]);
         memset(rec.str_current_update_time, '\0', sizeof(rec.str_current_update_time));
  	     strcpy(rec.str_current_update_time,word[12]);   	     
  	     rec.current_delete_time = atoi(word[13]);
  	     memset(rec.str_current_delete_time,'\0',sizeof(rec.str_current_delete_time));
  	     strcpy(rec.str_current_delete_time,word[14]); 	  
         memset(rec.latest_vlr, '\0', sizeof(rec.latest_vlr));
  	     strcpy(rec.latest_vlr,word[15]);
  	     rec.latest_update_time = atoi(word[16]);
         memset(rec.str_latest_update_time, '\0', sizeof(rec.str_latest_update_time));
  	     strcpy(rec.str_latest_update_time,word[17]);    	     
  	     rec.latest_delete_time = atoi(word[18]);
         memset(rec.str_latest_delete_time, '\0', sizeof(rec.str_latest_delete_time));
  	     strcpy(rec.str_latest_delete_time,word[19]);   	     

	       PutToContext(imsi_cond, &rec);				
			   curr_i++;
		 }
	 }
	}
  printf("chk.redirect_capacity=[%d]\n",chk.redirect_capacity);
  printf("������ curr_i=[%d]��\n", curr_i);
	close(fd_map);
	
	return 1;
}


int read_physical_area_info()
{
	// ȡ�ü�¼����
	int physical_area_num = 0;
	//physical_area_num = read_physical_area_num(chk.physical_area_table_name, chk.physical_area_table_cel);
	printf("physical_area_num=[%d]\n", physical_area_num);

	// ����ռ�
    m_physical_area=(char**)malloc((physical_area_num)*sizeof(*m_physical_area));
    *m_physical_area=(char*)malloc((physical_area_num)*21*sizeof(**m_physical_area));
    for(int i=0; i<(physical_area_num); i++)
    {
        m_physical_area[i]=*m_physical_area+21*i;
    }        
    
    for(int i=0; i<physical_area_num; i++)
    {
       memset(m_physical_area[i], '\0', 21);  
    }
    
	read_physical_area(chk.physical_area_table_name, chk.physical_area_table_cel);
	
	/*
    for(int i=0; i<physical_area_num; i++)
    {
		printf("m_physical_area[%d]=[%s]\n\n", i, m_physical_area[i]);
    }	
	*/

	return physical_area_num;
}

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
	fp = fopen("../etc/event_type.list", "r");
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

void read_event_type_wld()
{

		
      
        //m_event_type.insert(make_pair("1111", "2222"));

	printf("qqqqqqqqqqqqqqqqqqqqqqqq\n");	
	/*
    for(m_pos_event_type=m_event_type.begin(); m_pos_event_type!=m_event_type.end(); ++m_pos_event_type)
    {
        printf("[%s]\n", (*m_pos_event_type).c_str());
    }
	*/
    

	
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
	fp = fopen("../etc/saRoamMonitor_decode_map.conf", "r");
	if(fp==NULL){
		printf("���ļ�decode_map.conf����\n");
		exit(-1);
	}
	
	memset(str_decode_map_tmp, '\0', sizeof(str_decode_map_tmp));
	memset(str_decode_map, '\0', sizeof(str_decode_map));
	while(fgets(str_decode_map_tmp, 1024, fp)!=NULL)
	{
		if(str_decode_map_tmp[strlen(str_decode_map_tmp)-1] == '\n'){
			strncpy(str_decode_map, str_decode_map_tmp, strlen(str_decode_map_tmp)-1);
		}else{
			strncpy(str_decode_map, str_decode_map_tmp, strlen(str_decode_map_tmp));
		}

		if(str_decode_map[0] == '#'){
			memset(str_decode_map_tmp, '\0', sizeof(str_decode_map_tmp));
			memset(str_decode_map, '\0', sizeof(str_decode_map));		
			continue;
		}
		
		//printf("str_decode_map=[%s]\n", str_decode_map);
		loop = 0;
		p_field = strtok(str_decode_map, ",");
		while(p_field){
			loop ++;			
			LTrim(p_field, ' ');
			RTrim(p_field, ' ');				
			if(loop == 1){
				memset(field_name, '\0', sizeof(field_name));
				strcpy(field_name, p_field);
				//printf("field_name=[%s]\n", field_name);
			}
				
			if(loop == 2){
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
	
	//ȥhlr��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "hlr");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end()){
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_hlr_num = m_pos_decode_map->field_id - 1;
		//printf("field_other_party_num=[%d]\n", field_other_party_num);
	}		

	//ȡvlr��Ӧ��ID���
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "vlr");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end()){
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_vlr_num = m_pos_decode_map->field_id - 1;
		//printf("field_other_party_num=[%d]\n", field_other_party_num);
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

	DIR		 *dp;
	struct dirent *entry;
	struct stat	buf;
	char	 *ptr;
	#define MAXLINES 100
	char *fileptr[MAXLINES];

	char input_file_path[200];
	char input_file_backup_path[200];
	
	char input_file_name[200];

	set<string> 				m_input_file_name;
	set<string>::iterator 		m_pos_m_input_file_name;

	// �ж��Ƿ���ֹͣ��־�ļ�
	int fd_exit;
	char str_exit_file_name[200];
	memset(str_exit_file_name, '\0', sizeof(str_exit_file_name));
	strcpy(str_exit_file_name, "../lib/exitflag");
		
	// ȡ�������ļ�·��
	memset(input_file_path, '\0', sizeof(input_file_path));
	strcpy(input_file_path, chk.nonparticipant_file_path);
	//printf("input_file_path=[%s]\n", input_file_path);

			
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
    
			//printf("wld 1111 ��ǰ�ļ���[%s]\n", input_file_name);
    
			if (lstat(input_file_name, &buf) < 0)
			{
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
			
			fd_exit =open(str_exit_file_name, O_RDONLY);
			if(fd_exit>0) {
				printf("��⵽ֹͣ�ļ����ڣ������˳���\n");	
				exitflag=1;
				close(fd_exit);
				remove(str_exit_file_name);
				break;
			}
		}

		if(exitflag <= 0)
		{
			fd_exit =open(str_exit_file_name, O_RDONLY);
			if(fd_exit>0) {
				printf("��⵽ֹͣ�ļ����ڣ������˳���\n");	
				exitflag=1;
				close(fd_exit);
				remove(str_exit_file_name);
			}
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


int  find_physical_area(char *physical_area)
{
    int         iRet = 0;
    int         iRet_DB = 0;

    int         lLeft = 0;
    long        lMiddle = 0;
    int         lRight = physical_area_num - 1;
         
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
   /**********************************************************/
	/*************** ��ȡ�¼����Ϳ�ʼ *************************/
	/**********************************************************/
	memset(&m_pstn_area_info, '\0', sizeof(m_pstn_area_info));
	printf("���ع��ڳ�;������Ϣ\n");
	//read_pstn_area_info("DIM_PSTN_AREA_INFO", "AREA_CODE", "AREA_TYPE");
	read_pstn_area_info(chk.pstn_area_info_table_name, "AREA_CODE", "AREA_TYPE");
	
	/*
	for(int i=0;i<1000;i++)
	{
		if(m_pstn_area_info[i] != 0)
		{
			printf("m_pstn_area_info[%i]=[%d]\n",i, m_pstn_area_info[i]);
		}
	}
	*/
	
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
	
	/*
    for(int i=0; i<msisdn_num; i++)
    {
			printf("m_msisdn_info[%d]=[%s]\n", i, m_msisdn_info[i]);
    }	
	*/

	/*
	int ret = find_msisdn_area_info("1352161");
	printf("ret=[%d]\n", ret);

	ret = find_msisdn_area_info("1352169");
	printf("ret=[%d]\n", ret);
	*/

    return 0;
}

// �����ֻ�����ǰ׺ά����Ϣ
int read_mobile_prefix_info()
{
	memset(&mobile_prefix_area, '\0', sizeof(mobile_prefix_area));

	// ȡ�ü�¼��
	mobile_prefix_num = read_mobile_prefix_num(chk.mobile_prefix_table_name, "PREFIX_NUMBER","");
	
	// ����ռ�
  mobile_prefix_area=(char**)malloc((mobile_prefix_num)*sizeof(*mobile_prefix_area));
  *mobile_prefix_area=(char*)malloc((mobile_prefix_num)*10*sizeof(**mobile_prefix_area));
  for(int i=0; i<mobile_prefix_num; i++)
  {
      mobile_prefix_area[i]=*mobile_prefix_area+10*i;
  }        
  
  for(int i=0; i<mobile_prefix_num;i++)
  {
     memset(mobile_prefix_area[i], '\0', 10);
  }

	read_mobile_prefix(chk.mobile_prefix_table_name, "PREFIX_NUMBER,PREFIX_TYPE", "");
	
	/*
	for(int i=0; i<mobile_prefix_num; i++)
  {
			//printf("mobile_prefix_area[%d]=[%s]\n", i, mobile_prefix_area[i]);
			printf("mobile_prefix_area[%d]=[%s] mobile_prefix_type[%d]=[%d] \n", i, mobile_prefix_area[i],i, mobile_prefix_type[i]);
  }	
	*/
	
  return mobile_prefix_num;
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

	/*
    for(int i=0; i<msisdn_num; i++)
    {
			printf("m_msisdn_info[%d]=[%s]\n\n", i, m_msisdn_info[i]);
    }	
    */

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

	/*
	p_field = strtok((char*)(access_numbers.c_str()), ",");
	while(p_field)
	{
		//printf("p_field=[%s]\n", p_field);
		m_access_number.insert(p_field);

		p_field = strtok(NULL, ",");
	}

	
    for(m_pos_access_number=m_access_number.begin(); m_pos_access_number!=m_access_number.end(); ++m_pos_access_number)
    {
        printf("[%s]\n", (*m_pos_access_number).c_str());
    }
	*/

	/*
	int ret = find_spec_services_info("17951");
	printf("[%d]\n", ret);

	ret = find_spec_services_info("1795");
	printf("[%d]\n", ret);

	ret = find_spec_services_info("qqqq");
	printf("[%d]\n", ret);
	*/

    return 0;
}



int find_spec_services_info(char *access_number)
{
	/*
	m_pos_access_number = m_access_number.find(access_number);
    if(m_pos_access_number == m_access_number.end())
    {
    	return 0;	
    }
	else
	{
    	return 1;
	}
	*/

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

	/*
    for(int i=0; i<numbers_prefix_info_num; i++)
    {
			printf("m_numbers_prefix_info[%d]=[%s]\n", i, m_numbers_prefix_info[i]);
    }	
	*/

	/*
	int ret = find_prefix_info("12593123456");
	printf("ret=[%d]\n", ret);

	ret = find_prefix_info("11111112345");
	printf("ret=[%d]\n", ret);

	ret = find_prefix_info("11234567");
	printf("ret=[%d]\n", ret);
	*/

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

int  find_mobile_prefix_info(char *numbers, int prefix_type)
{
  int iRet = 0;

	char str_numbers[30];

	memset(str_numbers, '\0', sizeof(str_numbers));
	strcpy(str_numbers, numbers);

  int         lLeft = 0;
	long        lMiddle = 0;
	int         lRight = mobile_prefix_num - 1;

	while(lLeft <= lRight)
	{
		lMiddle = (lLeft + lRight) / 2;
		iRet = strncmp(mobile_prefix_area[lMiddle], str_numbers,strlen(mobile_prefix_area[lMiddle]));
		//printf("mobile_prefix_area[%d]=[%s]\n", lMiddle,mobile_prefix_area[lMiddle]);
		//printf("length=%d\n", strlen(mobile_prefix_area[lMiddle]));
		if(iRet == 0)
		{
			//printf("find mobile_prefix_area[%d]=[%s]\n", lMiddle,mobile_prefix_area[lMiddle]);
			//����ǰ׺�ҵ�����Ϊ��Ӧ��Ӫ������
			if(mobile_prefix_type[lMiddle] == prefix_type)
			{ 
					return lMiddle;
			}
			else
			{
					return -1;
			}	
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

	return -1;
	
}

//��������ȫ���û���Ϣ
int export_roam_file(){
	int ret;
  char buff[300];
  char filename[100];
  char sqlstring[200];	
	
	#ifdef _DB2_				
	  printf("��ʼɾ�� roam_user_info.txt \n");
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "rm -fr roam_user_info.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);
	  
	  printf("��ʼ���� roam_user_info.txt \n");	
	  memset(filename, 0, sizeof(filename));
	  strcpy(filename, "roam_user_info.txt");		
	  memset(sqlstring, 0, sizeof(sqlstring));
	  strcpy(sqlstring, "select distinct imsi,bill_id,HLR,last_enter_time from ");
	  strcat(sqlstring, chk.roam_table_name);
	  strcat(sqlstring, " where ");	
	  strcat(sqlstring, chk.roam_select_cond);	
	  strcat(sqlstring, " and (last_leave_time is null or length(last_leave_time) <= 0)");
	  ret = export_data (sqlstring, filename);
	  printf("����roam_user_info.txt, ret=%d \n",ret);
    
	  printf("��ʼȥ���ļ�����˫���ţ�roam_user_info.txt \n");		
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "sed s/\\\"//g roam_user_info.txt > roam_user_info.txt.tmp");
	  printf("buff = [%s]\n", buff);
	  system(buff);
	  
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "mv  roam_user_info.txt.tmp roam_user_info.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);	
	#endif //_DB2_ 	
   
  return 1;	
}


//��������ȫ���û���Ϣ
int export_roamchange_file(){
	int ret;
  char buff[300];
  char filename[100];
  char sqlstring[200];	
	
	#ifdef _DB2_				
	  printf("��ʼɾ�� roam_change_info.txt \n");
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "rm -fr roam_change_info.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);
	  
	  printf("��ʼ���� roam_change_info.txt \n");	
	  memset(filename, 0, sizeof(filename));
	  strcpy(filename, "roam_change_info.txt");		
	  memset(sqlstring, 0, sizeof(sqlstring));
	  strcpy(sqlstring, "select distinct imsi,bill_id,HLR,last_enter_time,LAST_LEAVE_TIME from ");
	  strcat(sqlstring, chk.roam_table_name);
	  strcat(sqlstring, " where ");	
	  strcat(sqlstring, chk.roam_select_cond);	
	  strcat(sqlstring, " and force_leave_flag = 1");
	  ret = export_data (sqlstring, filename);
	  printf("���� roam_change_info.txt, ret=%d \n",ret);
    
	  printf("��ʼȥ���ļ�����˫���ţ�roam_change_info.txt \n");		
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "sed s/\\\"//g roam_change_info.txt > roam_change_info.txt.tmp");
	  printf("buff = [%s]\n", buff);
	  system(buff);
	  
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "mv  roam_change_info.txt.tmp roam_change_info.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);	
	#endif //_DB2_ 	
   
  return 1;	
}

//��ʼ��HLR����Ϣ��������HLR�����ַ����飬�Զ��Ÿ���
int read_hlr_list(){
	int ret;
  char buff[300];
  char filename[100];
  char sqlstring[200];	
	int	fd_map;
	char line[40];
	FileBuff fb_map;
	char *word[50];	
	int len[50];	
  char hlr[18];
	fb_map.num=0;
	fb_map.from=0;
	int num=1;	
			
	#ifdef _DB2_				
	  printf("��ʼɾ�� hlr_list_info.txt \n");
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "rm -fr hlr_list_info.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);
	  
	  printf("��ʼ���� hlr_list_info.txt \n");	
	  memset(filename, 0, sizeof(filename));
	  strcpy(filename, "hlr_list_info.txt");		
	  memset(sqlstring, 0, sizeof(sqlstring));
	  strcpy(sqlstring, "select distinct hlr_id from ");
	  strcat(sqlstring, chk.hlr_table_name);
	  strcat(sqlstring, " where ");	
	  strcat(sqlstring, chk.hlr_select_cond);	
	  ret = export_data (sqlstring, filename);
	  printf("����hlr_list_info.txt, ret=%d \n",ret);
    
	  printf("��ʼȥ���ļ�����˫���ţ�hlr_list_info.txt \n");		
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "sed s/\\\"//g hlr_list_info.txt > hlr_list_info.txt.tmp");
	  printf("buff = [%s]\n", buff);
	  system(buff);
	  
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "mv  hlr_list_info.txt.tmp hlr_list_info.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);	
	  //system(buff);		  
	  printf("HLR�ļ��������...\n");	  
	#endif //_DB2_ 		
	
	//��ȡ��¼��
	hlrCounts= count_rows(chk.hlr_table_name, chk.hlr_select_cond);
	printf("in read_hlr_list,hlrCounts=%d\n",hlrCounts);
	
	//���ͷſռ�
	if(hlrList != NULL) free(hlrList);
	
	//�������ڴ�ռ�
	hlrList = (char **)Malloc(sizeof(char *)*hlrCounts);
	for(int i=0 ; i < hlrCounts ; i++){
	   hlrList[i] = (char *)Malloc(sizeof(char)*16);	
	}

	fd_map=open("hlr_list_info.txt", O_RDONLY);
	int nums = 0 ;
	while(num>0){
		num = ReadLine(fd_map, &fb_map, line, MAXLINE);	// ��num==0ʱ����ʾ�ѵ����ļ�β�����޿ɶ�ȡ������		
		if( num > 0 ) {			
			memset(word, '\0', sizeof(word));						
			ret=Split(line, ',', 50, word, len);
			memset(hlr, '\0', sizeof(hlr));
			strcpy(hlr, word[0]);
			LTrim(hlr, ' ');
			RTrim(hlr, ' '); 
			
			memset(hlrList[nums],'\0',sizeof(hlrList[nums]));
			strcpy(hlrList[nums],hlr); 	
			printf("hlrList[%d]=[%s]\n",nums,hlrList[nums]);
			nums++;
		}
	}
	close(fd_map); 
	 
	memset(buff, 0, sizeof(buff));
	strcpy(buff, "rm -fr hlr_list_info.txt");
	printf("buff = [%s]\n", buff);
	system(buff);	
	memset(buff, 0, sizeof(buff));
	strcpy(buff, "rm -fr tbexport.MSG");
	printf("buff = [%s]\n", buff);
	system(buff);	
	printf("HLR�ļ�ɾ�����...\n");
  return 1;
}

int read_vlr_list(){
	int ret;
  char buff[300];
  char filename[100];
  char sqlstring[200];	
	int	fd_map;
	char line[40];
	FileBuff fb_map;
	char *word[50];	
	int len[50];	
  char vlr[16];
	fb_map.num=0;
	fb_map.from=0;
	int num=1;	
			
	#ifdef _DB2_				
	  printf("��ʼɾ�� vlr_list_info.txt \n");
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "rm -fr vlr_list_info.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);
	  
	  printf("��ʼ���� vlr_list_info.txt \n");	
	  memset(filename, 0, sizeof(filename));
	  strcpy(filename, "vlr_list_info.txt");		
	  memset(sqlstring, 0, sizeof(sqlstring));
	  strcpy(sqlstring, "select distinct vlr_id from ");
	  strcat(sqlstring, chk.vlr_table_name);
	  strcat(sqlstring, " where ");	
	  strcat(sqlstring, chk.vlr_select_cond);	
	  ret = export_data (sqlstring, filename);
	  printf("����vlr_list_info.txt, ret=%d \n",ret);
    
	  printf("��ʼȥ���ļ�����˫���ţ�vlr_list_info.txt \n");		
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "sed s/\\\"//g vlr_list_info.txt > vlr_list_info.txt.tmp");
	  printf("buff = [%s]\n", buff);
	  system(buff);
	  
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "mv  vlr_list_info.txt.tmp vlr_list_info.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);	
	  printf("VLR�ļ��������...\n");	  
	#endif //_DB2_ 		
	
	//��ȡ��¼��
	vlrCounts= count_rows(chk.vlr_table_name, chk.vlr_select_cond);
	printf("in read_hlr_list,vlrCounts=%d\n",vlrCounts);
	
	//���ͷſռ�
	if(vlrList != NULL) free(vlrList);
			
	//�������ڴ�ռ�
	vlrList = (char **)Malloc(sizeof(char *)*vlrCounts);
	for(int i=0 ; i < vlrCounts ; i++){
	   vlrList[i] = (char *)Malloc(sizeof(char)*16);	
	}

	fd_map=open("vlr_list_info.txt", O_RDONLY);
	int nums = 0 ; 
	while(num>0){
		num = ReadLine(fd_map, &fb_map, line, MAXLINE);	// ��num==0ʱ����ʾ�ѵ����ļ�β�����޿ɶ�ȡ������		
		if( num > 0 ) {			
			memset(word, '\0', sizeof(word));						
			ret=Split(line, ',', 50, word, len);
			
			memset(vlr, '\0', sizeof(vlr));
			strcpy(vlr, word[0]);
			LTrim(vlr, ' ');
			RTrim(vlr, ' '); 
			
			memset(vlrList[nums],'\0',sizeof(vlrList[nums]));
			strcpy(vlrList[nums],vlr);  
			printf("vlrList[%d]=[%s]\n",nums,vlrList[nums]);			
			nums++;	
		}
	}
	close(fd_map); 
		
	memset(buff, 0, sizeof(buff));
	strcpy(buff, "rm -fr vlr_list_info.txt");
	printf("buff = [%s]\n", buff);
	system(buff);	
	memset(buff, 0, sizeof(buff));
	strcpy(buff, "rm -fr tbexport.MSG");
	printf("buff = [%s]\n", buff);
	system(buff);
	printf("VLR�ļ�ɾ�����...\n");		
	 
  return 1;
}