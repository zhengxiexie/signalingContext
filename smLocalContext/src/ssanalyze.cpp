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




// 增加初始化互斥锁
pthread_mutex_t pthread_init_mutex;

// 解码变量的设置
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

// 增加过滤互斥锁
pthread_mutex_t filtrate_mutex;

// 日志互斥锁
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

	char msisdn[30];	// 本端号码
	char tmp_msisdn[30]; //临时存储号码，以处理ps接口使用主叫、被叫时要区分本端问题
	char errinfo[200];	
	
	char str_tmp[2];
	time_t event_time;
	
	char event_type[10];	
	char str_user_event_type[10];
	char lac_id[10], str_lac_id[10];
	char ci_id[10], str_ci_id[10];
	char lac_ci_id[20];
	char str_event_time[20];	
	
	char local_prov_flag[MAX_LOCAL_PROV_FLAG_LEN] ;			  // 是否本省用户 1本省用户 0非本省用户
	char prov_code[MAX_PROV_CODE_LEN];	// 本省编码	
	char city_code[MAX_CITY_CODE_LEN];	// 地市编码
			
	struct tm *tp;
	
	int pthread_id;
	
	pthread_id = pthread_self();
	
	memset(&rec, '\0', sizeof(rec));	
    
	printf("处理线程[%d]启动...\n", pthread_id);

	while(1)
	{
		pthread_mutex_lock(&lb.mutex);
		while( lb.lines <= 0 && exitflag==0 )
		{	
			pthread_cond_wait(&lb.more, &lb.mutex);
		}

    //缓冲区处理完毕才能退出
    //if((lb.lines <= 0) && (exitflag>0) && (file_read_exitflag > 0))
		if((lb.lines <= 0) && (exitflag != 0))
		{
			//正常退出时，需要把上下文中内容先输出到结果文件缓冲区,
			//再把缓冲区写入文件，关闭文件
		  //重新启动则不会丢位置数据，保证整体连续
		  //正常退出相当于做初始化   20100409
			//上下文信息输出到缓冲
			//实时营销不需要把上下文中内容先输出到结果文件缓冲区
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
			sprintf(errinfo,"上下文处理线程退出,立即检查！");		   
			printf("%s\n",errinfo);
			write_error_file(chk.err_file_path,"smLocalContext","64",2,errinfo);				
			pthread_exit(0);
		}

		memset(line_tmp, '\0', sizeof(line_tmp));
		memset(line, '\0', sizeof(line));
		
		ret = GetLine(&lb, line);
		//printf("当前处理信令数据为=[%s]\n", line);

		pthread_cond_signal(&lb.less);
		pthread_mutex_unlock(&lb.mutex);
    
		//解析信令数据
		strcpy(line_tmp, line);		
		ret=Split(line_tmp, ',', 50, word, len);
		
		//printf("line_tmp=[%s]\n", line_tmp);
		//printf("line=%s", line);

    //imsi长度不为15位，则为错误数据
		if(strlen(word[field_imsi_num]) != 15)
		{
		  memset(errinfo,'\0',sizeof(errinfo));
		  sprintf(errinfo,"imsi长度不为15位，imsi=[%s] 请关注。", word[field_imsi_num]);	
		  //printf("imsi长度不为15位 请关注 line=%s", line);  
		  write_error_file(chk.err_file_path,"smLocalContext","7",2,errinfo);		
		  continue;
		}
				
		//取得imsi
		memset(imsi, '\0', sizeof(imsi));
		strcpy(imsi, word[field_imsi_num]);
		LTrim(imsi, ' ');
		RTrim(imsi, ' ');
		//printf("imsi=[%s]\n", imsi);

		//取得手机号码信息开始
		memset(msisdn, '\0', sizeof(msisdn));
		memset(tmp_msisdn, '\0', sizeof(tmp_msisdn));
		
		memset(event_type, '\0', sizeof(event_type));
		strcpy(event_type, word[field_event_type_num]);
		//printf("event_type=[%s]\n", event_type);
			
		/*	
		PS域号码互换由预处理部分完成
		if(strcmp(event_type, "702") == 0 )		//PS域被叫时 取被叫端为本端号码
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

		
		//使用信令中号码时，当号码前缀为86时，剔除前缀86
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
    //使用信令中号码时，当剔除86后号码长度不为11位，则剔除
		if(( 1 == chk.imsi_msisdn_flag ) && (strlen(msisdn)!=11) )
		{
       continue;	
		}
		
		//printf("msisdn1=[%s]\n", msisdn);

		memset(&rec, '\0', sizeof(rec));	
		memset(str_result, '\0', sizeof(str_result));

		//从信令事件时间中截取19位
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
		//修改lac、cell为空剔除条件，为空同时不为漫游出省601时剔除
		
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
		// ====================== 相关过滤处理结束 =================================
		// =========================================================================

		memset(&rec, '\0', sizeof(rec));	
		memset(str_result, '\0', sizeof(str_result));

		//lac、cell为0或-1均表示错误
		if ( (0 == strcmp(lac_id, "-1")) || (0 == strcmp(lac_id, "0"))  || (0 == strcmp(ci_id, "-1")) || (0 == strcmp(ci_id, "0"))  ){
			tp = localtime(&event_time);
			sprintf(str_event_time, "%4d-%02d-%02d %02d:%02d:%02d",
			tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	
		  memset(errinfo,'\0',sizeof(errinfo));
		  sprintf(errinfo,"lac、cell错误，imsi=[%s],event_time=[%s]请关注。", imsi,str_event_time);	
		  //printf("lac、cell错误，请关注 line=%s", line);   
		  write_error_file(chk.err_file_path,"smLocalContext","66",2,errinfo);	
		  continue;					
		}
		
	  //配置为不需要外省用户时则直接剔除外省
		if ( (1 == chk.other_prov_flag) && (0 == strcmp(local_prov_flag, "0")) ){
		  continue;					
		}		
		
		pthread_mutex_lock(&chk.mutex);
			
		ret=GetFromContext(imsi, &rec);	
		if( -1 == ret ) {
			  
			  //直接剔除条件
			  //1:号码为空
			  //2:省份标识为空
			  //3:配置为剔除外省用户，类型为外省用户
				if((strlen(msisdn) == 0) || (strlen(local_prov_flag) == 0) ) {
						//imsi不在映射表时剔除条件
						//1:号码为空 
						//2号码不为空，但为本省用户(或为未知省份用户)
						//printf("-1 == ret imsi=%s\n",imsi);
						pthread_mutex_unlock(&chk.mutex);
						continue;
				}
								  
			  if((1 == chk.imsi_msisdn_flag)){
						//printf("before InsertContext,context_capacity=%d,context_capacity_used=%d\n",chk.context_capacity,chk.context_capacity_used);		 
				  	
				  	//预分配上下文空间用完，则新imsi不动态插入
						if(chk.context_capacity <= chk.context_capacity_used){
				  	   memset(errinfo,'\0',sizeof(errinfo));
			    	   sprintf(errinfo,"用户[%s]超过上下文的最大容量，该客户信息丢弃，请关注。", line);		   
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
								//imsi不在映射表时剔除条件
								//1：号码为空
								//2：号码不为空，但为本省用户(或为未知省份用户)
								//printf("-1 == ret imsi=%s\n",imsi);
								pthread_mutex_unlock(&chk.mutex);
								continue;						
						}

				  	//预分配上下文空间用完，则新imsi不动态插入
						if(chk.context_capacity <= chk.context_capacity_used){
				  	   memset(errinfo,'\0',sizeof(errinfo));
			    	   sprintf(errinfo,"用户[%s]超过上下文的最大容量，该客户信息丢弃，请关注。", line);		   
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
			  		printf("配置imsi_msisdn_flag选项错误\n");
						pthread_mutex_unlock(&chk.mutex);
						continue;			  	
			  }
		} 
		
		ret = update_user_info(word, &rec, str_result);
		//testGet(imsi);
		
		pthread_mutex_unlock(&chk.mutex);
		
		// 打印信令中IMSI在上下文中对应的信息
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

	char msisdn[30];	// 本端号码
	char opp_num[MAX_OTHER_NUMBERS_LEN];	// 对端号码

	// 初始化赋值，防止指针为空
	char* msisdn_cleanout = "1111";		// 本端号码
	char* opp_num_cleanout = "2222";	// 对端号码

	char lac_ci_id[20];

	time_t curr_system_time;
	char str_curr_system_time[20];

	struct tm *tp;
	
	int ret=0;//当本次lac-cell与上下文中lac-cell不同时为1 否则为0 为1表示要更新上下文中lac-cell
  int ruleid;

	char str_tmp[2];
	
	int lac_ci_flag = 0;

	// =======================================================
	// ============= 取得手机号码信息开始 ====================
	// =======================================================
	memset(msisdn, '\0', sizeof(msisdn));
	
	//无论是从imsi、msisdn映射表取号码，还是从信令数据取号码，均先保存，再使用，
	//以满足同一imsi信令数据有时没提供号码也能正常输出
	strcpy(msisdn, rec->msisdn);
	//printf("in update_user_info msisdn=[%s]\n", msisdn);
	// =======================================================
	// ============= 取得手机号码信息结束 ====================
	// =======================================================

	// =======================================================
	// =========== 取得信令中各字段内容开始 ==================
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
	
	//事件原因码字段有的省市可能没有，则设置为空
	memset(cause, '\0', sizeof(cause));
  if(field_cause_num >= 0)
  {
		strcpy(cause, word[field_cause_num]);
	}
	//printf("cause=[%s]\n", cause);

	memset(opp_num, '\0', sizeof(opp_num));
	
	/*
	PS域号码互换由预处理部分完成
	if(strcmp(event_type, "702") == 0 )		//PS域被叫时 取主叫端为对端号码
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
	// =========== 取得信令中各字段内容结束 ==================
	// =======================================================


	// 取得系统当前时间
	memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
	time(&curr_system_time);
	tp = localtime(&curr_system_time);
	sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_curr_system_time=[%s]\n", str_curr_system_time);


	//printf("rec->last_cell=[%s]\n", rec->last_cell);
	// -------------------------------------------------------
	// -------------- 修改上下文信息开始 ---------------------
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
			
	//更新信令事件时间
	rec->ler_time = event_time;
	
	strcpy(rec->cause, cause);
	
	memset(rec->last_cell, '\0', sizeof(rec->last_cell));
	strcpy(rec->last_cell, lac_ci_id);
	
	// 更新统计信息
	rec->smo_sms_counts = 0;
	rec->calling_call_counts = 0;
	rec->calling_call_duration = 0;
	rec->mobile_status = '0';
	rec->smt_sms_counts = 0;
	rec->called_call_counts = 0;
	rec->called_call_duration = 0;
	rec->mo_mms_counts = 0;
	rec->mt_mms_counts = 0;
	
	// 更新进入小区时间、离开小区时间、驻留时间
	rec->leave_time = 0;
	rec->resident_time = 0;

	// 初始化对段号码部分
	memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));

	// 初始化对段号码归属地信息(打电话)
	memset(rec->calling_other_party_area, '\0', sizeof(rec->calling_other_party_area));

	// 初始化对段号码归属地信息(接电话)
	memset(rec->called_other_party_area, '\0', sizeof(rec->called_other_party_area));

	if(strcmp(event_type, "101") == 0)		// 打电话
	{
		rec->calling_call_counts++;
		rec->calling_call_duration += duration;
  
		// 当对端号码有值时 更新对端号码
		if(strlen(opp_num) > 0)
		{
			/*
			// 号码清洗
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
			
			// 号码清洗
			//opp_num_cleanout = numbers_cleanout(opp_num);
			// action_type: 1-打电话 发短信 发彩信 2-接电话 接短信 接彩信
			//update_other_party_area(1, msisdn_cleanout, opp_num_cleanout, rec);
		}
	}
	else if(strcmp(event_type, "102") == 0)	// 接电话
	{
		rec->called_call_counts++;
		rec->called_call_duration += duration;
  
		// 当对端号码有值时
		if(strlen(opp_num) > 0)
		{
			memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "B");
			strcat(rec->other_numbers, opp_num);
			
			// 号码清洗
			//opp_num_cleanout = numbers_cleanout(opp_num);
			// action_type: 1-打电话 发短信 发彩信 2-接电话 接短信 接彩信
			//update_other_party_area(2, msisdn_cleanout, opp_num_cleanout, rec);
		}
	}
	else if(strcmp(event_type, "201") == 0)	// 发短信
	{
		rec->smo_sms_counts++;
  
		// 当对端号码有值时
		if(strlen(opp_num) > 0)
		{
		  memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "C");
			strcat(rec->other_numbers, opp_num);
			
			// 号码清洗
			//opp_num_cleanout = numbers_cleanout(opp_num);
			// action_type: 1-打电话 发短信 发彩信 2-接电话 接短信 接彩信
			//update_other_party_area(1, msisdn_cleanout, opp_num_cleanout, rec);
		}
	}
	else if(strcmp(event_type, "202") == 0)	// 接短信
	{
		rec->smt_sms_counts++;
  
		// 当对端号码有值时
		if(strlen(opp_num) > 0)
		{
			memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "D");
			strcat(rec->other_numbers, opp_num);

			// 号码清洗
			//opp_num_cleanout = numbers_cleanout(opp_num);
			// action_type: 1-打电话 发短信 发彩信 2-接电话 接短信 接彩信
			//update_other_party_area(2, msisdn_cleanout, opp_num_cleanout, rec);				
		}
	}
	else if(strcmp(event_type, "701") == 0)	// 发彩信
	{
		rec->mo_mms_counts++;
  
		// 当对端号码有值时
		if(strlen(opp_num) > 0)
		{
		  memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "E");
			strcat(rec->other_numbers, opp_num);
			
			// 号码清洗
			//opp_num_cleanout = numbers_cleanout(opp_num);
			//printf("opp_num=[%s] opp_num_cleanout=[%s]\n", opp_num,opp_num_cleanout);
			// action_type: 1-打电话 发短信 发彩信 2-接电话 接短信 接彩信
			//update_other_party_area(1, msisdn_cleanout, opp_num_cleanout, rec);
			//printf("opp_num=[%s] opp_num_cleanout=[%s] rec->other_numbers=[%s] \n", opp_num,opp_num_cleanout,rec->other_numbers);	
		}
	}
	else if(strcmp(event_type, "702") == 0)	// 接彩信
	{
		rec->mt_mms_counts++;
  
		// 当对端号码有值时
		if(strlen(opp_num) > 0)
		{
			memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
			strcpy(rec->other_numbers, "F");
			strcat(rec->other_numbers, opp_num);

			// 号码清洗
			//opp_num_cleanout = numbers_cleanout(opp_num);
			// action_type: 1-打电话 发短信 发彩信 2-接电话 接短信 接彩信
			//update_other_party_area(2, msisdn_cleanout, opp_num_cleanout, rec);				
		}
	}		
	else if((strcmp(event_type, "301") == 0) || (strcmp(event_type, "302") == 0) || (strcmp(event_type, "303") == 0) || (strcmp(event_type, "401") == 0) || (strcmp(event_type, "402") == 0))	// 正常位置更新 301正常位置更新 302正常位置更新 401 小区切换-切入 402 小区切换-切出
	{
		// 更新位置信息
		//rec->last_action_type = event_type;
		//strcpy(rec->last_action_type, event_type);
		
		// 计算停留时间 当前时间-进入时间
		//使用当前信令数据时间戳-进入时间更准确
		//rec->resident_time = (event_time - rec->come_time)/60;
		//rec->resident_time = (curr_system_time - rec->come_time)/60;
		//printf("rec->resident_time=[%d] chk.resident_time_raft=[%d]\n", rec->resident_time, chk.resident_time_raft);
	}
	else if(strcmp(event_type, "501") == 0)	// 开机
	{
		rec->mobile_status = '2';
	}
	else if(strcmp(event_type, "502") == 0)	// 关机
	{
		rec->mobile_status = '1';
	}
		
	strcpy(rec->last_action_type, event_type);
  
  GetResultStr(rec, 0, str_result_tmp);

	//printf("ruleid=[%d] str_result_tmp=%s", ruleid, str_result_tmp);
	  	
  pthread_mutex_lock(&filtrate_mutex);
	// 输出到结果文件中

	WriteResult(ruleid, str_result_tmp);		
	pthread_mutex_unlock(&filtrate_mutex);
	
	//printf("after GetResultStr() rec->last_cell=[%s] \n",rec->last_cell);	
	// -------------------------------------------------------
	// -------------- 修改上下文信息开始 ---------------------
	// -------------------------------------------------------

	return ret;	
}

/*
// 号码清洗
// 1. 当以86、0086开头时，去除
// 2. a. 取得1步操作后的号码，
//	  b. 当其长度大于8时（如果小于8位，取其实际长度），取前8位（如果小于8位，取其实际长度）字符串长度为i, 在DIM_NUMBERS_PREFIX_INFO中查找
//	  c. 当b步没有查找到时，做i--
//	  d. if(i<3) 退出查找
// 3. 如果2步有匹配的字符串，去除操作后，再次检查是否以86、0086开头时，去除
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

	// 当清洗后的号码长度小于等于3时，说明清洗有问题，将原号码返回
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

	// 使用清洗后的号码判断其是否在特服号码信息表中
	ret = find_spec_services_info(opp_num_cleanout);
	if(ret == 0)
	{
		//printf("没找到\n");
		return -1;
	}
	//printf("找到\n");

	// 向文件的输出还使用原有号码
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
		// 取得系统当前时间
		memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
		time(&curr_system_time);
		tp = localtime(&curr_system_time);
		sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
		tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
		//printf("str_curr_system_time=[%s]\n", str_curr_system_time);
		
		// 更新停留时间
		rec->resident_time = (curr_system_time - rec->come_time)/60;

		// 判断当前用户对应的小区信息是否在逻辑区表中
		pthread_mutex_lock(&filtrate_mutex);
		memset(lac_ci_id, '\0', sizeof(lac_ci_id));
		strncpy(lac_ci_id, rec->last_cell, 11);
		int res_physical_area = 0;
		res_physical_area = find_physical_area(lac_ci_id);
    	if(res_physical_area != 0)
   		{
			// 取得切换前的上下文信息
			GetResultStr(rec, 0, str_result_tmp);
			//printf("str_result_tmp=[%s]\n", str_result_tmp);				
			
			ret=1;
		}
		else
		{
			ret=0;
		}

		// 清楚当前上下文信息中的other_numbers字段内容
		memset(rec->other_numbers, '\0', sizeof(rec->other_numbers));
		strcpy(rec->other_numbers, str_prefix);
		strcat(rec->other_numbers, opp_num);
		strcat(rec->other_numbers, "|");
		//printf("清除imsi=[%s] 的other_numbers字段内容\n", imsi);

		pthread_mutex_unlock(&filtrate_mutex);
	}
	else
	{	
		// 取得calling_call_numbers
		strcat(rec->other_numbers, str_prefix);
		strcat(rec->other_numbers, opp_num);
		strcat(rec->other_numbers, "|");
	}

	//strcpy(str_result_tmp, (rec->other_numbers).c_str());
	//printf("imsi=[%s] 的 rec->other_numbers=[%s]\n", imsi, rec->other_numbers);
	
	return ret;	
}


void update_other_party_area(int action_type, char *msisdn_cleanout, char * opp_num_cleanout, Context *rec)
{
	char opp_area_code[5];
	int opp_area_type = 0;

	char msisdn_4[5];
	char msisdn_3[4];

	char opp_area_info[10];

	// 取得本端和对端取号信息
	// 格式：区号类型（1位）@区号代码（将“0”去掉，2-3位）
	// 举例：2@551
	int opp_area_flag = 0; // 标识是否找到对端号码归属地信息

	memset(opp_area_info, '\0', sizeof(opp_area_info));
	
	//printf("msisdn_cleanout=[%s] opp_num_cleanout=[%s]\n", msisdn_cleanout, opp_num_cleanout);


	// 国外号码判断
	// 以"00"开头号码，不再区分是国外那个国家
	if(strncmp(opp_num_cleanout, "00", 2)  == 0)
	{
		opp_area_flag = 1;
		strcpy(opp_area_info, "4@00");
		//printf("msisdn_cleanout=[%s] opp_num_cleanout=[%s] opp_area_code=[%s]\n", msisdn_cleanout, opp_num_cleanout,opp_area_code);
	}
	else if((strncmp(opp_num_cleanout, "0", 1) == 0) && (strncmp(opp_num_cleanout, "00", 2) != 0) && (strlen(opp_num_cleanout) > 5))
	{
		// 判断外地固定电话号码标准
		// 当对端号码以"0"开头并且不以"00"开头,并且长度大于5时,取得对应的长途区号
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
				//printf("对端为固话时[%s]未找到其对应信息！\n", opp_num_cleanout);
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
		//printf("对端为固话时所属地区信息：opp_area_info=[%s]\n", opp_area_info);
	}
	else if((strncmp(opp_num_cleanout, "1", 1) == 0) && (strlen(opp_num_cleanout) == 11))
	{
		// 判断手机号码标准
		// 当对端号码以"1"开头并且长度等于11时
		int ret_find_msisdn = find_msisdn_area_info(opp_num_cleanout);
		//printf("m_msisdn_info[%d]=[%s]\n", ret_find_msisdn, m_msisdn_info[ret_find_msisdn]);
		
		if(ret_find_msisdn != -1)
		{
			strcpy(opp_area_info, m_msisdn_info[ret_find_msisdn]+8);
			//printf("对端为手机时所属地区信息：opp_area_info=[%s]\n", opp_area_info);
			
			opp_area_flag = 1;
		}
		else
		{
			//printf("对端为手机时[%s]未找到其所属地区的对应信息！\n", opp_num_cleanout);
		}
	}
	else
	{
		//printf("在判断对端号码[%s]归属地信息时，对端号码格式不符合判断标准！\n", opp_num_cleanout);
	}

	// 当对端号码找到归属地信息时
	if(opp_area_flag == 1)
	{
		// calling_other_party_area或called_other_party_area格式：
		// 格式：区号类型（1位）@区号代码（将“0”去掉，2-3位）
		// 举例：2@551 （2-省内 3-省外 4-国外）

		// 根据传入的事件类型,进行不同操作
		if(action_type == 1)	// 打电话 发短信 发彩信
		{
				memset(rec->calling_other_party_area, '\0', sizeof(rec->calling_other_party_area));
				strcat(rec->calling_other_party_area, opp_area_info);
		}
		else	// 接电话 接短信 接彩信
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

	// 取得本端和对端取号信息
	// 格式：区号类型（1位）@区号代码（将“0”去掉，2-3位）
	// 举例：2@551
	int opp_area_flag = 0;

	//printf("msisdn_cleanout=[%s] opp_num_cleanout=[%s]\n", msisdn_cleanout, opp_num_cleanout);

	opp_area_flag = 0;	// 标识是否找到对端号码归属地信息
	memset(opp_area_info, '\0', sizeof(opp_area_info));
	// 国外号码判断
	// 以"00"开头的号码，不再区分是国外那个国家
	if(strncmp(opp_num_cleanout, "00", 2) == 0)
	{
		strcpy(opp_area_code, "4@00");
	}
	// 判断外地固定电话号码标准
	// 当对端号码以"0"开头并且不以"00"开头,并且长度大于5时,取得对应的长途区号
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
				//printf("对端为固话时[%s]未找到其对应信息！\n", opp_num_cleanout);
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
		//printf("对端为固话时所属地区信息：opp_area_info=[%s]\n", opp_area_info);
	}
	// 判断手机号码标准
	// 当对端号码以"1"开头并且长度等于11时
	else if((strncmp(opp_num_cleanout, "1", 1) == 0) && (strlen(opp_num_cleanout) == 11))
	{
		int ret_find_msisdn = find_msisdn_area_info(opp_num_cleanout);
		//printf("m_msisdn_info[%d]=[%s]\n", ret_find_msisdn, m_msisdn_info[ret_find_msisdn]);
		
		if(ret_find_msisdn != -1)
		{
			strcpy(opp_area_info, m_msisdn_info[ret_find_msisdn]+8);
			//printf("对端为手机时所属地区信息：opp_area_info=[%s]\n", opp_area_info);
			
			opp_area_flag = 1;
		}
		else
		{
			//printf("对端为手机时[%s]未找到其所属地区的对应信息！\n", opp_num_cleanout);
		}
	}
	else
	{
		//printf("在判断对端号码[%s]归属地信息时，对端号码格式不符合判断标准！\n", opp_num_cleanout);
	}

	// 找到对端号码归属地信息
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
				//printf("本端所属地区信息：msisdn_area_info=[%s]\n", msisdn_area_info);
			}
			else
			{
				//printf("本端号码[%s]所属地区未找到其对应信息！\n", msisdn_cleanout);
			}
		}
		else
		{
			//printf("在判断对端号码[%s]归属地信息时，本端号码格式不符合判断标准！\n", opp_num_cleanout);
		}
	}

	// 当对端号码找到归属地信息时
	if(opp_area_flag == 1)
	{
		//printf("对端号码归属地信息[%s] 本端号码归属地信息[%s]\n", opp_area_info, msisdn_area_info);
		
		// 判断本端号码与对端号码的归属地是否相同
		// 当不相同时，认为对端为外地用户
		// calling_other_party_area或called_other_party_area格式：
		// 格式：区号类型（1位）@区号代码（将“0”去掉，2-3位）
		// 举例：2@551 （2-省内 3-省外 4-国外）
		if(strcmp(opp_area_info, msisdn_area_info) != 0)
		{
			// 根据传入的事件类型,进行不同操作
			if(action_type == 1)	// 打电话
			{
				if((strlen(rec->calling_other_party_area) + strlen(opp_area_info) + 2) > MAX_AREA_LEN)
				{
					//printf("action_type=[%d]\n", action_type);
					// 清楚当前上下文信息中的other_numbers字段内容
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
			else	// 接电话
			{
				if((strlen(rec->called_other_party_area) + strlen(opp_area_info) + 2) > MAX_AREA_LEN)
				{
					//printf("action_type=[%d]\n", action_type);
					// 清楚当前上下文信息中的other_numbers字段内容
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

// time_flag=1时，离开时间取系统当前时间
// time_flag=0时，离开时间取rec中对应字段的时间
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

	// 取得系统当前时间
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
	//========== 对lac_id,ci_id处理开始 ==================
	//====================================================
	//strncat(line, rec->last_cell, 11);
	//strcat(line,",");

	memset(last_cell, '\0', sizeof(last_cell));
	//printf("000 rec->last_cell=[%s] last_cell=[%s]\n", rec->last_cell, last_cell);
	strncat(last_cell, rec->last_cell, 11);
	//printf("111 rec->last_cell=[%s] last_cell=[%s] line=%s \n", rec->last_cell, last_cell,line);
	
	//当事件类型为601、602 漫游时 lac,cell为空，需要添加空值
	if( strncmp(last_cell, "-",1) == 0 )
	{
		strcat(line,",");
	} 
		else
	{
		strcat(line, last_cell);
		strcat(line,",");
	}
	
  //输出信令事件时间 以利于实时营销使用 20091117
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
		
	/*	xiamw 20100120 lac-cell 不做拆分	
	//当事件类型为601 漫游时 lac,cell为空，需要添加空值
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
	//========== 对lac_id,ci_id处理结束 ==================
	//====================================================
	
	//当“当前手机状态”字段 开机为2时，开机为1
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
	// 取得对段号码信息，由于直接对内存操作，需要加锁
	pthread_mutex_lock(&chk.mutex);
	string other_numbers;
	map<string, InfoStat>::iterator m_PosNumber_Info;
	// 根据imsi信息查找
	m_PosNumber_Info = m_Number_Info.find(rec.imsi);
	// 当存在对段号码信息时，取得放入rec中
	if(m_PosNumber_Info != m_Number_Info.end())
	{
		other_numbers = m_PosNumber_Info->second.other_numbers;
		
		// 删除最后一个逗号
		other_numbers.erase(other_numbers.size()-1);
		//printf("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeevvv      other_numbers=[%s]\n", other_numbers.c_str());
	}

	strcat(line, other_numbers.c_str());
	strcat(line, "|");
	pthread_mutex_unlock(&chk.mutex);
	*/

	//==========================================================================
	//=========================== 对段号码处理开始 =============================
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
	//=========================== 对段号码处理结束 =============================
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

	//输出本省，外省标识 1表示外省 0 表示本省
	sprintf(tmp,"%s,",rec->local_prov_flag);
	strcat(line, tmp);
	
	//输出省份-地市编码	
	strcat(line, rec->prov_code);
	strcat(line,"-");		
	strcat(line, rec->city_code);
	strcat(line,",");		

	//输出事件类型 以利于即时营销使用 20091117
	sprintf(tmp,"%s,",rec->last_action_type);
	strcat(line, tmp);
	//新增事件类型处理离开，以利于即时营销使用 20091117
	
	//输出事件原因码 20100118
	sprintf(tmp,"%s",rec->cause);
	strcat(line, tmp);
	//新增事件原因码 20100118
	
	//输出换行符
	strcat(line, "\n");
	
  //屏蔽输出系统时间，改为输出信令事件时间 以利于即时营销使用 20091117	
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

    // 当timeout时间到，有数据则输出文件，否则不输出
		if( ana.counts[ruleid]>0 ) 
		{
			// 当timeout时间到，但缓存还没有写满过信息，需要将输出文件描述符打开
			if(ana.fd[ruleid]<=0)
			{
				ana.fd[ruleid] = open(ana.fname[ruleid], O_APPEND|O_WRONLY|O_CREAT, 0644);
			}
			//printf("1111 ana.num[ruleid]=[%d] dest=[%s]\n", ana.num[ruleid], dest);
			WriteN(ana.fd[ruleid], dest, ana.num[ruleid]);
			//WriteN_wld(ana.fd[ruleid], dest, ana.num[ruleid]);
			close(ana.fd[ruleid]);

			// 取得系统当前时间
			time_t sys_time;
			char str_sys_time[20];
			memset(str_sys_time, '\0', sizeof(str_sys_time));
			sys_time = get_system_time_2(str_sys_time);

			memset(tmp, '\0', sizeof(tmp));
			char fname_tmp[200];
			memset(fname_tmp, '\0', sizeof(fname_tmp));
			strncpy(fname_tmp, ana.fname[ruleid], strlen(ana.fname[ruleid])-4);
			sprintf(tmp, "%s_%s", fname_tmp, str_sys_time);
			
			//输出后缀名不为空，并且首字母不为"."时则自动补"."
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
			// 删除装载成功的文件
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

	// 输出smLocalContext.conf文件配置信息
	PrintCfg(cfg);
	
	/*
	//连接数据库，连接不上则退出
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
	//最大容量由初始化设置决定
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
		printf("获取imsi总数量信息开始...\n");
  	
		chk.context_capacity = count_rows(chk.table_name, chk.select_cond);
		
		//测试使用 20091121 20091218
		//chk.context_capacity = 263;//349933;//25000000
		
		printf("获取imsi总数量信息结束\n\n");
	*/

	time_t begin_time, end_time;
	char str_begin_time[20], str_end_time[20];
	memset(str_begin_time, '\0', sizeof(str_begin_time));
	begin_time = get_system_time(str_begin_time);
	//printf("str_begin_time=[%s]\n", str_begin_time);
	printf("上下文空间内存分配与初始化开始 str_begin_time=[%s]...\n", str_begin_time);
  
	// 上下文空间分配
	context = (BCDContext *)Malloc(sizeof(BCDContext)*chk.context_capacity);
	
  if(!context)
  {	
  	printf("Not Enough Memory in context !\n");
  	exit(1);
  }
  	
	// 上下文空间初始化
	/*bzero(context, sizeof(BCDContext)*chk.context_capacity);20090326*/
	memset(context, '\0', sizeof(BCDContext)*chk.context_capacity);
	
 	 			
	// 主索引空间分配与初始化
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
 			// 附属索引空间分配
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
  		
  		//因后面连续分配内存空间可能因连续内存空间不足而失败，
  		//故而预先分配和改为和上下文一样数量的重定向索引内存空间，启动时一次分配完
			redirect = (BCDIndex *)Malloc(sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune));
			for(i=0; i<chk.context_capacity-chk.hash_tune; i++){
				redirect[i].offset=redirect[i].redirect= -1;
			}			 
	}
	*/

  chk.context_capacity_used = 0; 
  //chk.redirect_capacity = 0;
  
  //因后面连续分配内存空间可能因连续内存空间不足而失败，
  //故而预先分配和改为和上下文一样数量的重定向索引内存空间，启动时一次分配完
	redirect = (BCDIndex *)Malloc(sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune));
	for(i=0; i<chk.context_capacity-chk.hash_tune; i++){
		redirect[i].offset=redirect[i].redirect= -1;
	}		
			
					 		
	memset(str_end_time, '\0', sizeof(str_end_time));
	end_time = get_system_time(str_end_time);
	//printf("str_end_time=[%s]\n", str_end_time);
	printf("上下文空间内存分配与初始化结束 str_end_time=[%s]\n\n", str_end_time);
  
	printf("显示上下文占用内存信息开始...\n");
	printf("sizeof(BCDContext) is %dB\n", sizeof(BCDContext));
	printf("sizeof(BCDIndex) is %dB.\n\n", sizeof(BCDIndex));
  
	printf("subscribers:%d\n", chk.context_capacity);
  
	size = sizeof(BCDContext)*chk.context_capacity;
	printf("上下文[Context]占用内存:%.2f MB\n", size/1048576);
  
	size = sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune);
	printf("上下文主索引[Index]占用内存:%.2f MB\n", size/1048576);
  
	//if(chk.imsi_msisdn_flag == 0)
	//{  
	//	size=sizeof(BCDIndex)*chk.redirect_capacity;
	//}
	//else 
	//{
	//	size=sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune);
	//}
	
	size=sizeof(BCDIndex)*(chk.context_capacity-chk.hash_tune);
	printf("上下文附属索引[Reindex]占用内存:%.2f MB\n", size/1048576);
	printf("显示上下文占用内存信息结束\n\n");
			
	if(chk.imsi_msisdn_flag == 0)
	{  				
			// ===================================================================================
			// ===================== 加载imsi与msisdn对应关系信息开始 ============================
			//====================================================================================
			memset(str_begin_time, '\0', sizeof(str_begin_time));
			begin_time = get_system_time(str_begin_time);
			//printf("str_begin_time=[%s]\n", str_begin_time);
			printf("加载imsi与msisdn对应关系信息开始 str_begin_time=[%s]...\n", str_begin_time);
			
			InitContext();
				
			memset(str_end_time, '\0', sizeof(str_end_time));
			end_time = get_system_time(str_end_time);
			//printf("str_end_time=[%s]\n", str_end_time);
			printf("加载imsi与msisdn对应关系信息结束 str_end_time=[%s]\n\n", str_end_time);
			printf("conflict_subscribers:%d\n\n", chk.redirect_capacity);
			// ===================================================================================
			// ===================== 加载imsi与msisdn对应关系信息结束 ============================
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
	

	//读取信令解码映射
	printf("解码对应关系...\n");
	read_decode_info();
	printf("解码对应关系结束\n");


  /**********************************************************/
	/******** 为了保证初始化的完成，休眠一段时间 **************/
	/**********************************************************/
	//sleep(10);

  //程序主体启动完成,写心跳文件
  char moudleName[250] ;
  memset(moudleName,'\0',sizeof(moudleName));
  sprintf(moudleName,"%ssmLocalContext.proc",chk.proc_file_path);
  write_heart_file(moudleName);
  
  //读取完数据后，即关闭数据库连接20110509
  //close_db();
  
	// 配置采用何种方式取得信令数据
	//PthreadCreate(&tid_produce, &attr, produce_fr_tcp, NULL); // socked的tcp方式
	PthreadCreate(&tid_produce, &attr, produce_fr_ftp, NULL); // 直接读ftp传输到指定目录下的文件方式（只是读取文件部分）

	// 启动load线程
	PthreadCreate(&tid_monitor, NULL, load_timer, NULL);

	// 启动备份线程
	//PthreadCreate(&tid_backup, NULL, backup_timer, NULL);

	// 启动定时输出日志线程
	PthreadCreate(&tid_log, NULL, log_timer, NULL);
	
	// 启动处理线程
	tid_consume=(pthread_t*)Malloc(chk.analyze_thread_num*sizeof(pthread_t));
	for(i=0; i<chk.analyze_thread_num; i++) 
	{
		PthreadCreate(tid_consume+i, &attr, consume, NULL);
	}
	

	// 等待采集线程，备份线程，上下文处理线程结束
	// 初始化线程，输出线程不等待其结束
	// 由于输出线程不等待其结束，在输出线程启动输出的过程中，对其进行停止，可能会造成输出记录不完整
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

  //因日志输出休眠时间为5分钟，影响退出，故不等待直接退出
	//pthread_join(tid_log, NULL);
	
	printf("读到退出标识，程序退出 \n");

	memset(errinfo,'\0',sizeof(errinfo));
	sprintf(errinfo,"客户程序退出，请立即检查！");		   
	write_error_file(chk.err_file_path,"smLocalContext","61",2,errinfo);	
	
	exit(0);
}


/*
int read_physical_area_info()
{
	// 取得记录行数
	int tmp_physical_area_num = 0;
	//physical_area_num = read_physical_area_num(chk.physical_area_table_name, chk.physical_area_table_cel);
	printf("physical_area_num=[%d]\n", tmp_physical_area_num);

	// 分配空间
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
	/*************** 读取事件类型开始 *************************/
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
		printf("打开文件event_type.list错误！\n");


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
			printf("str_event_type=[%s]长度不能大于10字节\n", str_event_type);
			printf("程序退出！\n");
			
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
	/*************** 读取事件类型结束 *************************/
	/**********************************************************/	


    /**********************************************************/
	/************ 分配内存与加载信息开始 **********************/
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
	/************ 分配内存与加载信息结束 **********************/
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
		printf("打开文件decode_map.conf错误！\n");

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

	
	// 取得IMSI对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "imsi");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_imsi_num = m_pos_decode_map->field_id - 1;
		//printf("field_imsi_num=[%d]\n", field_imsi_num);
	}

	// 取得msisdn对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "msisdn");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		field_msisdn_num = m_pos_decode_map->field_id - 1;
	}
	
	// 取得event_type对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "event_type");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_event_type_num = m_pos_decode_map->field_id - 1;
		//printf("field_event_type_num=[%d]\n", field_event_type_num);
	}

	// 取得time_stamp对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "time_stamp");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_time_stamp_num = m_pos_decode_map->field_id - 1;
		//printf("field_time_stamp_num=[%d]\n", field_time_stamp_num);
	}
	
	// 取得duration对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "duration");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_duration_num = m_pos_decode_map->field_id - 1;
		//printf("field_duration_num=[%d]\n", field_duration_num);
	}

	// 取得lac_id对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "lac_id");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_lac_id_num = m_pos_decode_map->field_id - 1;
		//printf("field_lac_id_num=[%d]\n", field_lac_id_num);
	}

	// 取得ci_id对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "ci_id");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_ci_id_num = m_pos_decode_map->field_id - 1;
		//printf("field_ci_id_num=[%d]\n", field_ci_id_num);
	}
	
	// 取得cause对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "cause");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_cause_num = m_pos_decode_map->field_id - 1;
		//printf("field_cause_num=[%d]\n", field_cause_num);
	}
	
	// 取得other_party对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "other_party");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_other_party_num = m_pos_decode_map->field_id - 1;
		//printf("field_other_party_num=[%d]\n", field_other_party_num);
	}

	// 取得other_party对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "local_prov_flag");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_local_prov_flag_num = m_pos_decode_map->field_id - 1;
		//printf("field_local_prov_flag_num=[%d]\n", field_local_prov_flag_num);
	}
	
	// 取得other_party对应的ID编号
	memset(&m_Stat, '\0', sizeof(m_Stat));
	strcpy(m_Stat.field_name, "prov_code");
	m_pos_decode_map = m_decode_map.find(m_Stat);
	if(m_pos_decode_map != m_decode_map.end())
	{
		//printf("m_pos_decode_map.field_id=[%d]\n", m_pos_decode_map->field_id);
		field_prov_code_num = m_pos_decode_map->field_id - 1;
		//printf("field_prov_code_num=[%d]\n", field_prov_code_num);
	}
	
	// 取得other_party对应的ID编号
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

	// 取得输入文件路径
	memset(input_file_path, '\0', sizeof(input_file_path));
	strcpy(input_file_path, chk.nonparticipant_file_path);
	printf("input_file_path=[%s]\n", input_file_path);

			
	if((dp = opendir(input_file_path)) == NULL)
	{
		printf("路径[%s]打开错误！\n", input_file_path);

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
    
			printf("wld 1111 当前文件名[%s]\n", input_file_name);
    
			if (lstat(input_file_name, &buf) < 0)
			{
				continue;
			}
			
			if(strstr(input_file_name, ".tmp") != NULL){
		      continue;
	    }	
			//printf("wld 2222 当前文件名[%s]\n", input_file_name);
    
			if (!S_ISREG(buf.st_mode))
			{
				continue;
			}
    
			//printf("wld 2222 %s %ld %ld \n",input_file_name,buf.st_atime,buf.st_mtime);
			m_input_file_name.insert(entry->d_name);
    
		}  
    
		closedir(dp);
    
		//printf("取得每一个文件名...\n");
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
    
			printf("当前处理文件 [%s] str_begin_time=[%s]\n", input_file_name, str_begin_time);
			fflush(stdout);
    
			// 处理文件中的每条话单
			fd=open(input_file_name, O_RDONLY);
			num = 1;
			while(num>0)
			{
				// 取得文件中的每条记录
				num = ReadLine(fd, &fb, line, MAXLINE);	// 当num==0时，表示已到达文件尾或是无可读取的数据
    
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
    
			// 删除处理完成的文件
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


// 加载国内长途区号信息和移动号段信息
int read_area_info()
{

	memset(&m_pstn_area_info, '\0', sizeof(m_pstn_area_info));
	printf("加载国内长途区号信息\n");
	//read_pstn_area_info("DIM_PSTN_AREA_INFO", "AREA_CODE", "AREA_TYPE");
	read_pstn_area_info(chk.pstn_area_info_table_name, "AREA_CODE", "AREA_TYPE");
	
	printf("加载移动号码归属地区信息\n");
	// 取得记录数
	//msisdn_num = read_msisdn_info_num("DIM_MSISDN_INFO", "MSISDN_PREFIX");
	msisdn_num = read_msisdn_info_num(chk.msisdn_info_table_name, "MSISDN_PREFIX");
	printf("msisdn_num=[%d]\n", msisdn_num);
	
	// 分配空间
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


// 取得传入的手机号码的前7位，查找其归属的地区信息
// 返回值说明 -1=没找到 非-1时，为传入号码的前7位在结构中匹配上的索引位置
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
        // 取得字符串的前7位进行对比
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



// 加载特服号码信息
int read_spec_services_info()
{
	char* p_field;
	


	read_spec_services("DIM_SPEC_SERVICES", "ACCESS_NUMBER", access_numbers);
	printf("特服号码列表为=[%s]\n", access_numbers.c_str());

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

	printf("加载号码前缀信息\n");
	// 取得记录数
	//numbers_prefix_info_num = read_numbers_prefix_info_num("DIM_NUMBERS_PREFIX_INFO", "NUMBERS_PREFIX");
	numbers_prefix_info_num = read_numbers_prefix_info_num(chk.numbers_prefix_info_table_name, "NUMBERS_PREFIX");
	//printf("numbers_prefix_info_num=[%d]\n", numbers_prefix_info_num);
	
	// 分配空间
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
	printf("前缀列表为=[%s]\n", numbers_prefixs.c_str());
	
	p_field = strtok((char*)(numbers_prefixs.c_str()), ",");
	while(p_field)
	{
		//printf("p_field=[%s]\n", p_field);
		//排序
		m_prefix_info.insert(p_field);

		p_field = strtok(NULL, ",");
	}

	// 排序后输出
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

	// 当长度大于8时,截取前8个字节进行匹配查找
	memset(str_numbers, '\0', sizeof(str_numbers));
	strcpy(str_numbers, numbers);
    if(strlen(str_numbers) < i)
    {
    	i = strlen(str_numbers);
    }

	while(1)
	{
		// 当长度小于3时,认为没有找到
    	if(i<3)
    	{
    		return -1;
    	}

    	// 取得每次待比较的字符串
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
