/**
* Copyright (c) 2010 AsiaInfo. All Rights Reserved.                     
* Creator: zhoulb  email:zhoulb@asiainfo.com
* Modified log：
*	    1> zhoulb	2010-03-01	Create 
*     2> 
* Description: 
*      漫入漫出客户上下文处理函数，主程序调用
* 错误代码范围：
*       R1001 -- R2000 
**/

#include "sspublic.h"
#include "sscontext.h"
#include "ssanalyze.h"
#ifdef _ORACLE_
#include "ssoracle.h"
#endif /* _ORACLE */
#ifdef _DB2_
#include "ssdb2.h"
#endif /* _DB2_ */

//map<string, InfoStat> m_Number_Info;

//全局上下文和索引变量申明
BCDContext	*context;
BCDIndex	*Index;
BCDIndex	*redirect;

void *init_timer(void *arg)
{
	int ret;
	time_t begin_time,end_time,come_time,leave_time;
	char str_leave_time[30],str_come_time[30];
	char str_event_time[20];
	char str_begin_time[20],str_end_time[20];
	char imsi_cond[16],msisdn_cond[16],hlr[16],vlr[16];
	char line[500];
	char errinfo[200];
	Context rec;		
	FileBuff fb_map;
	int fd_map;
	char *word[50];	
	int len[50];
	int num ;
	FILE	*ftp_tmp;
	int index_num = 0;
	char buff[100];
			
	time_t t0,t1;
	struct tm *t;
		
	while(1){
		t1 = time(&t0);
		t0 = t1;		
		t1+=24*3600;
		t=localtime(&t1);
		t->tm_hour=chk.signal_check_interval;
		t->tm_min=0;
		t->tm_sec=0;

		t1 = mktime(t);
		sleep(t1-t0);
		
		//sleep(chk.signal_check_interval);				

		pthread_mutex_lock(&chk.mutex); 
		
	  //初始化上海HLR信息
	  ret = read_hlr_list();
	  //初始化上海VLR信息
	  ret = read_vlr_list();	
	    
	  memset(str_begin_time, '\0', sizeof(str_begin_time));
	  begin_time = get_system_time(str_begin_time);
	  printf("稽核漫游用户信息到上下文开始：str_begin_time=[%s]...\n", str_begin_time);		

		//0.通过库内漫游数据稽核上下文 
   	memset(line,'\0',sizeof(line)); 
		ret = export_roamchange_file();	    
    num = 1 ;
	  fd_map=open("roam_change_info.txt", O_RDONLY);
	  while( num > 0 ){
		  num = ReadLine(fd_map, &fb_map, line, 500);	// 当num==0时，表示已到达文件尾或是无可读取的数据		
		  if( num > 0 ) {
			   memset(&rec, '\0', sizeof(rec));			   
			   memset(word, '\0', sizeof(word));						
			   ret=Split(line, ',', 50, word, len);
			   
			   memset(imsi_cond, '\0', sizeof(imsi_cond));
			   strcpy(imsi_cond, word[0]);
			   LTrim(imsi_cond, ' ');
			   RTrim(imsi_cond, ' ');
			   
			   memset(msisdn_cond, '\0', sizeof(msisdn_cond));
			   strcpy(msisdn_cond, word[1]);
			   LTrim(msisdn_cond, ' ');
			   RTrim(msisdn_cond, ' ');
			   memset(rec.msisdn,'\0',sizeof(rec.msisdn));
			   strcpy(rec.msisdn,msisdn_cond);

         memset(hlr, '\0', sizeof(hlr));
  	     strcpy(hlr,word[2]);
			   LTrim(hlr, ' ');
			   RTrim(hlr, ' ');
			   memset(rec.hlr,'\0',sizeof(rec.hlr));
			   strcpy(rec.hlr,vlr);			     	     
			   	   
			   //进入时间
			   memset(str_come_time, '\0', sizeof(str_come_time));
			   strcpy(str_come_time, word[3]);
			   LTrim(str_come_time, ' ');
			   RTrim(str_come_time, ' ');  			   
			   str_come_time[10] = ' ';
			   str_come_time[13] = ':';
			   str_come_time[16] = ':';
			   
			   memset(str_event_time,'\0',sizeof(str_event_time));  
			   strncpy(str_event_time,str_come_time,19);
    	   come_time = ToTime_t(str_event_time);
    	   rec.come_time = come_time;
    	   
         memset(rec.str_come_time,'\0',sizeof(rec.str_come_time));
         strcpy(rec.str_come_time,str_come_time);
    	   
         //离开时间
			   memset(str_leave_time, '\0', sizeof(str_leave_time));
			   strcpy(str_leave_time, word[4]);
			   LTrim(str_leave_time, ' ');
			   RTrim(str_leave_time, ' '); 
			   str_leave_time[10] = ' ';
			   str_leave_time[13] = ':';
			   str_leave_time[16] = ':';
			    
			   memset(str_event_time,'\0',sizeof(str_event_time));  
			   strncpy(str_event_time,str_leave_time,19);
			   leave_time = ToTime_t(str_event_time);
			   rec.leave_time = leave_time;
			     	 	   			   
         memset(rec.str_leave_time,'\0',sizeof(rec.str_leave_time));
         strcpy(rec.str_leave_time,str_leave_time);
         
         //停留时间
         rec.resident_time = come_time - leave_time;
         //漫游状态
         rec.user_type = 0;             		
         ret = PutToContext(imsi_cond, &rec);		
	    }
	  }
	  close(fd_map); 
		
		memset(buff, 0, sizeof(buff));
	  strcpy(buff, "rm -fr roam_change_info.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);		
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "rm -fr tbexport.MSG");
	  printf("buff = [%s]\n", buff);
	  system(buff);		  
	  
	  //定期清理非漫游状态的上下文,user_type= 0;
	  //1.备份上下文漫游状态客户
	  printf("开始备份上下文信息,写入文件:context_user_backup.txt \n");
    ret = BackupContext("context_user_backup.txt");	  
	  printf("备份上下文信息完成,已经写入文件:context_user_backup.txt \n");	  

	  //2.清理上下文
	  memset(context, '\0', sizeof(BCDContext)*chk.context_capacity);		  
		for(int i=0; i<chk.context_capacity-chk.hash_tune; i++){
			memset(Index[i].imsi,'\0',sizeof(Index[i].imsi));
			Index[i].offset=Index[i].redirect= -1;
		}  
		for(int i=0; i<chk.context_capacity-chk.hash_tune; i++){
			memset(redirect[i].imsi,'\0',sizeof(redirect[i].imsi));
			redirect[i].offset=redirect[i].redirect= -1;
		}
  	chk.redirect_capacity = 0;
  	chk.context_capacity_used = 0;
  	memset(line,'\0',sizeof(line));
	  printf("上下文初始化完成... \n");	  	
	   		
	  //3.利用备份的上下文信息初始化上下文
	  num = 1;
	  int curr_i = 0;
	  fd_map=open("context_user_backup.txt", O_RDONLY);
	  while( num > 0 ){
		  num = ReadLine(fd_map, &fb_map, line, 500);	// 当num==0时，表示已到达文件尾或是无可读取的数据		
		  if( num > 0 ) {
			   memset(&rec, '\0', sizeof(rec));			   
			   memset(word, '\0', sizeof(word));						
			   ret=Split(line, ',', 50, word, len);
			   
			   memset(imsi_cond, '\0', sizeof(imsi_cond));
			   strcpy(imsi_cond, word[0]);
			   
			   memset(msisdn_cond, '\0', sizeof(msisdn_cond));
			   strcpy(msisdn_cond, word[1]);  	   
			   
				 if(chk.context_capacity <= chk.context_capacity_used){
				    memset(errinfo,'\0',sizeof(errinfo));
			      sprintf(errinfo,"漫入用户[%s]超过上下文的最大容量，该客户信息丢弃，请关注。", line);		   
			      write_error_file(chk.err_file_path,"saRoamMonitor","51",2,errinfo);								
					  continue;							
				 }
    	   ret = InsertContext(imsi_cond,msisdn_cond);									
         memset(rec.msisdn, '\0', sizeof(rec.msisdn));
  	     strcpy(rec.msisdn,msisdn_cond);
  	     rec.come_time = atoi(word[2]);
  	     rec.leave_time = atoi(word[3]); 	  
         memset(rec.str_come_time, '\0', sizeof(rec.str_come_time));
  	     strcpy(rec.str_come_time,word[4]);
         memset(rec.str_leave_time, '\0', sizeof(rec.str_leave_time));
  	     strcpy(rec.str_leave_time,word[5]);
  	     rec.resident_time = atoi(word[6]);
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
  	     if(rec.come_time == 0){
			     memset(str_event_time,'\0',sizeof(str_event_time));
			     strncpy(str_event_time,rec.str_come_time,19);
			     rec.come_time = ToTime_t(str_event_time);  	  	  
  	     }
	       PutToContext(imsi_cond, &rec);
			   curr_i++;	         		         		
	    }
	  }
	  close(fd_map); 	
  	printf("chk.redirect_capacity=[%d]\n",chk.redirect_capacity);
 	 	printf("共加载 curr_i=[%d]条\n", curr_i);	  
		printf("备份信息初始化上下文完成... \n");	
		 	  
	  //4.删除备份文件
		memset(buff, 0, sizeof(buff));
	  strcpy(buff, "rm -fr context_user_backup.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);
	    	  		
	  pthread_mutex_unlock(&chk.mutex);
	  
	  memset(str_end_time, '\0', sizeof(str_end_time));
	  end_time = get_system_time(str_end_time); 
	  printf("稽核漫游用户信息到上下文结束：end_time=[%s]\n\n", str_end_time);
	}
}

void init_timer(int event_hour)
{
	int ret;
	time_t begin_time,end_time,come_time,leave_time;
	char str_leave_time[30],str_come_time[30];
	char str_event_time[20];
	char str_begin_time[20],str_end_time[20];
	char imsi_cond[16],msisdn_cond[16],hlr[16],vlr[16];
	char line[500];
	char errinfo[200];
	Context rec;		
	FileBuff fb_map;
	int fd_map;
	char *word[50];	
	int len[50];
	int num ;
	FILE	*ftp_tmp;
	int index_num = 0;
	char buff[100];
	
	//当文件进行切换时，且等于预定的时间，则进行系统的初始化		
	if(event_hour >= 0 &&  event_hour == chk.signal_check_interval){		
	  //初始化上海HLR信息
	  ret = read_hlr_list();
	  //初始化上海VLR信息
	  ret = read_vlr_list();	
	    
	  memset(str_begin_time, '\0', sizeof(str_begin_time));
	  begin_time = get_system_time(str_begin_time);
	  printf("稽核漫游用户信息到上下文开始：str_begin_time=[%s]...\n", str_begin_time);		

		//0.通过库内漫游数据稽核上下文 
   	memset(line,'\0',sizeof(line)); 
		ret = export_roamchange_file();	    
    num = 1 ;
	  fd_map=open("roam_change_info.txt", O_RDONLY);
	  while( num > 0 ){
		  num = ReadLine(fd_map, &fb_map, line, 500);	// 当num==0时，表示已到达文件尾或是无可读取的数据		
		  if( num > 0 ) {
			   memset(&rec, '\0', sizeof(rec));			   
			   memset(word, '\0', sizeof(word));						
			   ret=Split(line, ',', 50, word, len);
			   
			   memset(imsi_cond, '\0', sizeof(imsi_cond));
			   strcpy(imsi_cond, word[0]);
			   LTrim(imsi_cond, ' ');
			   RTrim(imsi_cond, ' ');
			   
			   memset(msisdn_cond, '\0', sizeof(msisdn_cond));
			   strcpy(msisdn_cond, word[1]);
			   LTrim(msisdn_cond, ' ');
			   RTrim(msisdn_cond, ' ');
			   memset(rec.msisdn,'\0',sizeof(rec.msisdn));
			   strcpy(rec.msisdn,msisdn_cond);

         memset(hlr, '\0', sizeof(hlr));
  	     strcpy(hlr,word[2]);
			   LTrim(hlr, ' ');
			   RTrim(hlr, ' ');
			   memset(rec.hlr,'\0',sizeof(rec.hlr));
			   strcpy(rec.hlr,vlr);			     	    
			   	   
			   //进入时间
			   memset(str_come_time, '\0', sizeof(str_come_time));
			   strcpy(str_come_time, word[3]);
			   LTrim(str_come_time, ' ');
			   RTrim(str_come_time, ' ');  			   
			   str_come_time[10] = ' ';
			   str_come_time[13] = ':';
			   str_come_time[16] = ':';
			   
			   memset(str_event_time,'\0',sizeof(str_event_time));  
			   strncpy(str_event_time,str_come_time,19);
    	   come_time = ToTime_t(str_event_time);
    	   rec.come_time = come_time;
    	   
         memset(rec.str_come_time,'\0',sizeof(rec.str_come_time));
         strcpy(rec.str_come_time,str_come_time);
    	   
         //离开时间
			   memset(str_leave_time, '\0', sizeof(str_leave_time));
			   strcpy(str_leave_time, word[4]);
			   LTrim(str_leave_time, ' ');
			   RTrim(str_leave_time, ' '); 
			   str_leave_time[10] = ' ';
			   str_leave_time[13] = ':';
			   str_leave_time[16] = ':';
			    
			   memset(str_event_time,'\0',sizeof(str_event_time));  
			   strncpy(str_event_time,str_leave_time,19);
			   leave_time = ToTime_t(str_event_time);
			   rec.leave_time = leave_time;
			     	 	   			   
         memset(rec.str_leave_time,'\0',sizeof(rec.str_leave_time));
         strcpy(rec.str_leave_time,str_leave_time);
         
         //停留时间
         rec.resident_time = come_time - leave_time;
         //漫游状态
         rec.user_type = 0;             		
         ret = PutToContext(imsi_cond, &rec);		
	    }
	  }
	  close(fd_map); 
		
		memset(buff, 0, sizeof(buff));
	  strcpy(buff, "rm -fr roam_change_info.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);		
	  memset(buff, 0, sizeof(buff));
	  strcpy(buff, "rm -fr tbexport.MSG");
	  printf("buff = [%s]\n", buff);
	  system(buff);		  
	  
	  //定期清理非漫游状态的上下文,user_type= 0;
	  //1.备份上下文漫游状态客户
	  printf("开始备份上下文信息,写入文件:context_user_backup.txt \n");
    ret = BackupContext("context_user_backup.txt");	  
	  printf("备份上下文信息完成,已经写入文件:context_user_backup.txt \n");	  

	  //2.清理上下文
	  memset(context, '\0', sizeof(BCDContext)*chk.context_capacity);		  
		for(int i=0; i<chk.context_capacity-chk.hash_tune; i++){
			memset(Index[i].imsi,'\0',sizeof(Index[i].imsi));
			Index[i].offset=Index[i].redirect= -1;
		}  
		for(int i=0; i<chk.context_capacity-chk.hash_tune; i++){
			memset(redirect[i].imsi,'\0',sizeof(redirect[i].imsi));
			redirect[i].offset=redirect[i].redirect= -1;
		}
  	chk.redirect_capacity = 0;
  	chk.context_capacity_used = 0;
  	memset(line,'\0',sizeof(line));
	  printf("上下文初始化完成... \n");	  	
	   		
	  //3.利用备份的上下文信息初始化上下文
	  num = 1;
	  int curr_i = 0;
	  fd_map=open("context_user_backup.txt", O_RDONLY);
	  while( num > 0 ){
		  num = ReadLine(fd_map, &fb_map, line, 500);	// 当num==0时，表示已到达文件尾或是无可读取的数据		
		  if( num > 0 ) {
			   memset(&rec, '\0', sizeof(rec));			   
			   memset(word, '\0', sizeof(word));						
			   ret=Split(line, ',', 50, word, len);
			   
			   memset(imsi_cond, '\0', sizeof(imsi_cond));
			   strcpy(imsi_cond, word[0]);
			   
			   memset(msisdn_cond, '\0', sizeof(msisdn_cond));
			   strcpy(msisdn_cond, word[1]);  	   
			   
				 if(chk.context_capacity <= chk.context_capacity_used){
				    memset(errinfo,'\0',sizeof(errinfo));
			      sprintf(errinfo,"漫入用户[%s]超过上下文的最大容量，该客户信息丢弃，请关注。", line);		   
			      write_error_file(chk.err_file_path,"saRoamMonitor","51",2,errinfo);								
					  continue;							
				 }
    	   ret = InsertContext(imsi_cond,msisdn_cond);									
         memset(rec.msisdn, '\0', sizeof(rec.msisdn));
  	     strcpy(rec.msisdn,msisdn_cond);
  	     rec.come_time = atoi(word[2]);
  	     rec.leave_time = atoi(word[3]); 	  
         memset(rec.str_come_time, '\0', sizeof(rec.str_come_time));
  	     strcpy(rec.str_come_time,word[4]);
         memset(rec.str_leave_time, '\0', sizeof(rec.str_leave_time));
  	     strcpy(rec.str_leave_time,word[5]);
  	     rec.resident_time = atoi(word[6]);
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
  	     if(rec.come_time == 0){
			     memset(str_event_time,'\0',sizeof(str_event_time));
			     strncpy(str_event_time,rec.str_come_time,19);
			     rec.come_time = ToTime_t(str_event_time);  	  	  
  	     }
	       PutToContext(imsi_cond, &rec);
			   curr_i++;		          		         		
	    }
	  }
	  close(fd_map); 	
  	printf("chk.redirect_capacity=[%d]\n",chk.redirect_capacity);
 	 	printf("共加载 curr_i=[%d]条\n", curr_i);	  
		printf("备份信息初始化上下文完成... \n");	
		 	  
	  //4.删除备份文件
		memset(buff, 0, sizeof(buff));
	  strcpy(buff, "rm -fr context_user_backup.txt");
	  printf("buff = [%s]\n", buff);
	  system(buff);	    	  		
	  
	  memset(str_end_time, '\0', sizeof(str_end_time));
	  end_time = get_system_time(str_end_time); 
	  printf("稽核漫游用户信息到上下文结束：end_time=[%s]\n\n", str_end_time);
	}
}

void *backup_timer(void *arg)
{
	int fd;
	time_t sys_time;
	char str_sys_time[20];	
	char filename[200],rfilename[200];

	while(1) 
	{
		sleep(chk.backup_context_interval);

		// 取得系统当前时间
		memset(str_sys_time, '\0', sizeof(str_sys_time));
		sys_time = get_system_time_2(str_sys_time);
	  memset(filename, 0, sizeof(filename));
	  memset(rfilename, 0, sizeof(rfilename));
		sprintf(filename,"%ssaRoamMonitor.tmp",chk.log_file_path);
		sprintf(rfilename,"%ssaRoamMonitor_%d_%s.del",chk.log_file_path,getpid(),str_sys_time);		

		pthread_mutex_lock(&pthread_logfile_mutex);
		fd=open(filename, O_RDONLY);
		if(fd>0) {
		   rename(filename,rfilename);
 		   close(fd);
		}
		pthread_mutex_unlock(&pthread_logfile_mutex);
			
		if( exitflag > 0 && file_read_exitflag > 0) {
			exitflag=1;
			pthread_exit(0);
		}
	}
	return (NULL);
}

int InitContext(char *filename)
{
	int i;
	//char filename[100];

	//pthread_mutex_lock(&chk.mutex);

	/*for(i=0; i<chk.context_capacity-chk.hash_tune; i++){
		Index[i].offset=Index[i].redirect= -1;
	}
	
	for(i=0; i<chk.redirect_capacity; i++){            
		redirect[i].offset=redirect[i].redirect=-1;
	}*/
	
	 // 上下文读入从读表改为读数据文件
	//read_context(chk.table_name, chk.select_cond);
	
	#ifdef _DB2_
	//memset(filename, 0, sizeof(filename));
	//strcpy(filename, "roam_user_info.txt");
	
	read_context_file(filename);
	#endif //_DB2_ 

	#ifdef _ORACLE_
	read_context(chk.table_name, chk.select_cond);
	#endif //_DB2_ 	
	
	//printf("in InitContext read_context ok \n ");
	//pthread_mutex_unlock(&chk.mutex);
	
	return 0;
}


int InsertContext(char *imsi,char *msisdn)
{
	int pos,next;
	int ci,rj;
	int imsino = 0;
	//char bcdimsi[6];
	char bcdimsi[MAX_BCD_IMSI_LEN];
	
	char imsi_cond[16];
	char msisdn_cond[16];
	ci=rj=0;
	
	memset(imsi_cond, '\0', sizeof(imsi_cond));	
	memset(msisdn_cond, '\0', sizeof(msisdn_cond));	
	
	strcpy(imsi_cond, imsi);
	strcpy(msisdn_cond, msisdn);
	
	rj = chk.redirect_capacity;	
	ci = chk.context_capacity_used;		

  //memcpy(context[ci].msisdn,msisdn_cond, strlen(msisdn_cond));
  
	imsino = atoi(imsi_cond+6);
	pos = imsino % (chk.context_capacity-chk.hash_tune);
  
	Char2BCD(imsi_cond,  bcdimsi, 15);
	      
	    /*if(ci > 8581838){
	    	   if(Index[203154].offset != 3945111){
                printf("oooo==ismi=[%s],offset=[%d],redirect=[%d],ci=[%d],rj=[%d]\n",imsi_cond,Index[pos].offset,Index[pos].redirect,ci,rj);	    	   	
	    	   }
		       
	    	 
	    }*/
	      
	if( Index[pos].offset == -1) {
			Index[pos].offset = ci;
			memcpy(Index[pos].imsi,bcdimsi, MAX_BCD_IMSI_LEN);

	}else {
			next=Index[pos].redirect;  			 	
			if(next == -1){
				Index[pos].redirect = rj;
			}else{
				while(redirect[next].redirect != -1) {
					next=redirect[next].redirect;
				}
				redirect[next].redirect=rj;
			}
			
  		//因后面连续分配内存空间可能因连续内存空间不足而失败，
  		//故而预先分配和改为和上下文一样数量的重定向索引内存空间，启动时一次分配完			
			//重定向数量加1，
			//printf("imsi=[%s],redirect_capacity=[%d]\n",imsi_cond,chk.redirect_capacity);
			chk.redirect_capacity++;
			//redirect = (BCDIndex *)realloc(redirect,sizeof(BCDIndex)*chk.redirect_capacity);
			
			memcpy(redirect[rj].imsi,bcdimsi, MAX_BCD_IMSI_LEN);
			redirect[rj].offset = ci;
			redirect[rj].redirect = -1;			
	}
		
	chk.context_capacity_used++;	
	return 0;
}


int RestoreContext(char *fromfile)
{
	int backup_field_number=14; // 设置备份文件中每行记录的字段个数
	int i,j,fd,num=1;
	char lastch,*word[14];		// 在word[]中的字段个数设置必须是表达式常量，无法使用变量定义
	char line[1024], line_tmp[1024];
	Context rec;
	int ret;
	FileBuff fb;

	fb.num=0;
	fb.from=0;

	fd=open(fromfile, O_RDONLY);
	if(fd<0) {
		printf("Can't open %s,restore context failure.\n",fromfile);
		return -1;
	}

	//pthread_mutex_lock(&chk.mutex);
	while(num>0) 
	{
		memset(line_tmp, '\0', sizeof(line_tmp));
		memset(line, '\0', sizeof(line));
		num = ReadLine(fd, &fb, line_tmp, 1024);
		//printf("num=[%d] line_tmp=[%s]\n", num, line_tmp);
		
		if(line_tmp[strlen(line_tmp)-1] == '\n')
		{
			strncpy(line, line_tmp, strlen(line_tmp)-1);
		}
		else
		{
			strncpy(line, line_tmp, strlen(line_tmp));
		}
		//printf("line=[%s]\n", line);
		
		if( num >0 )
		{
			lastch='\0';
			for(i=0,j=0; i<num,j<backup_field_number; i++) {
				//if( line[i] != ',' )
				if( line[i] != '|' ) 
				{
					if( lastch == '\0' ) 
					{
						word[j]=line+i;
						j++;
					}
				}
				else line[i]='\0';
				lastch=line[i];
			}

			strcpy(rec.msisdn, word[0]);
			//strcpy(rec.imsi, word[1]);
			//strcpy(rec.last_cell, word[2]);
/*			rec.mobile_status = word[3][0];
			rec.smo_sms_counts = atoi(word[4]);
			rec.calling_call_counts = atoi(word[5]);
			rec.calling_call_duration= atoi(word[6]);
			rec.smt_sms_counts=atoi(word[7]);
			rec.called_call_counts = atoi(word[8]);
			rec.called_call_duration = atoi(word[9]);
			rec.come_time = ToTime_t(word[10]);
			rec.leave_time = ToTime_t(word[11]);
			rec.resident_time = atoi(word[12]);
			//rec.last_action_type = atoi(word[13]);
*/
			//memcpy(rec.end_cell, word[13], strlen(word[13]));

			//printf("wld 3333 11 word[9]=[%s]\n", word[9]);
			//printf("wld 3333 11 word[10]=[%s]\n", word[10]);
			//printf("wld 3333 11 word[11]=[%s]\n", word[11]);
			//printf("wld 3333 11 word[12]=[%s]\n", word[12]);
			//printf("wld 3333 11 word[13]=[%s]\n", word[13]);

			//pthread_mutex_lock(&chk.mutex);
			PutToContext(rec.imsi, &rec);
			//pthread_mutex_unlock(&chk.mutex);
		}
	}
	//pthread_mutex_unlock(&chk.mutex);
	close(fd);
	return 0;
}

int BackupContext(char *tofile)
{
	int i,fd;
	char imsi_cond[16], tmp[128];
	char line[500];
	FileBuff fb;
	Context rec;

	fb.num=0;
	fb.from=0;
	memset(fb.buf, '\0', FBUFFSIZE);
	fd=open(tofile, O_WRONLY|O_CREAT, 0644);
	if(fd<0) {
		printf("Can't open file:%s,backup context failure\n",tofile);
		return -1;
	}
	for(int i=0; i<(chk.context_capacity-chk.hash_tune); i++ ) {
		if(Index[i].offset != -1){
				// 取得输出字符串
				BCD2Char(Index[i].imsi, imsi_cond, 15);				
				GetFromContext(imsi_cond, &rec);
				if(rec.user_type == 1){
   					memset(line,'\0',sizeof(line));         
            sprintf(line,"%s,%s,%d,%d,%s,%s,%d,%s,%s,%d,%s,%d,%s,%d,%s,%s,%d,%s,%d,%s\n",
                 imsi_cond,rec.msisdn,rec.come_time,rec.leave_time,rec.str_come_time,
                 rec.str_leave_time,rec.resident_time,rec.hlr,rec.vlr,rec.user_type,rec.current_vlr,
                 rec.current_update_time,rec.str_current_update_time,rec.current_delete_time,rec.str_current_delete_time,
                 rec.latest_vlr,rec.latest_update_time,rec.str_latest_update_time,rec.latest_delete_time,rec.str_latest_delete_time); 
            WriteLine(fd, &fb, line, strlen(line));				             			   		
				}																	
		}
	}
  
	for(int i=0; i<chk.redirect_capacity; i++ ) {
		if(redirect[i].offset != -1) {	
				BCD2Char(redirect[i].imsi, imsi_cond, 15);
				GetFromContext(imsi_cond, &rec);
				if(rec.user_type == 1){
   					memset(line,'\0',sizeof(line));         
            sprintf(line,"%s,%s,%d,%d,%s,%s,%d,%s,%s,%d,%s,%d,%s,%d,%s,%s,%d,%s,%d,%s\n",
                 imsi_cond,rec.msisdn,rec.come_time,rec.leave_time,rec.str_come_time,
                 rec.str_leave_time,rec.resident_time,rec.hlr,rec.vlr,rec.user_type,rec.current_vlr,
                 rec.current_update_time,rec.str_current_update_time,rec.current_delete_time,rec.str_current_delete_time,
                 rec.latest_vlr,rec.latest_update_time,rec.str_latest_update_time,rec.latest_delete_time,rec.str_latest_delete_time); 
            
            WriteLine(fd, &fb, line, strlen(line));			
				}					
		}
	}	  
  if(fb.num>0)  write(fd, fb.buf, fb.num);
	close(fd);

	return 0;
}


int WriteContextBuf(int i, int fd, char *imsi, FileBuff *fb)
{
	char line[1024];
	char msisdn[16],last_cell[21],ca[3],tmp[BIG_MAXLINE];
	struct tm *tp;

	/*bzero(line,1024);*/
	memset(line, '\0', 1024);
	BCD2Char(context[i].msisdn, msisdn, 11);
	strcpy(line, msisdn);
	strcat(line,",");

	strcat(line, imsi);
	strcat(line,",");

/* xiamw 20100118

	//BCD2Char(context[i].last_cell, last_cell, 10);
	memset(last_cell, '\0', sizeof(last_cell));
	strncpy(last_cell, context[i].last_cell, 11);
	strcat(line, last_cell);
	strcat(line,",");

	// 当“当前手机状态”字段为空时，将其设置默认为0-状态不详
	if(context[i].mobile_status == '\0')
	{
		ca[0]='0';
	}
	else
	{
		ca[0]=context[i].mobile_status;
	}
	ca[1]=',';
	ca[2]='\0';
	strcat(line, ca);

	sprintf(tmp,"%d,",context[i].smo_sms_counts);
	strcat(line, tmp);

	sprintf(tmp,"%d,",context[i].calling_call_counts);
	strcat(line, tmp);

	sprintf(tmp,"%d,",context[i].calling_call_duration);
	strcat(line, tmp);

	sprintf(tmp,"%d,",context[i].smt_sms_counts);
	strcat(line, tmp);

	sprintf(tmp,"%d,",context[i].called_call_counts);
	strcat(line, tmp);

	sprintf(tmp,"%d,",context[i].called_call_duration);
	strcat(line, tmp);

	tp = localtime(&context[i].come_time);
	sprintf(tmp, "%4d-%02d-%02d %02d:%02d:%02d,",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	strcat(line, tmp);

	tp = localtime(&context[i].leave_time);
	sprintf(tmp, "%4d-%02d-%02d %02d:%02d:%02d,",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	strcat(line, tmp);

	sprintf(tmp,"%d,",context[i].resident_time);
	strcat(line, tmp);

	sprintf(tmp,"%s\n",context[i].last_action_type);
	strcat(line, tmp);
*/
	//printf("line=[%s]\n", line);
	WriteLine(fd, fb, line, strlen(line));
	return 0;
}


int GetFromContext(char *imsi, Context *rec)
{
	int i;

	i = FindIMSI(imsi);
	//printf("findIMSI return=[%d]\n",i);
	if(i != -1) {
		memset(rec->imsi,'\0',sizeof(rec->imsi));
		strcpy(rec->imsi, imsi);
		
		memset(rec->msisdn,'\0',sizeof(rec->msisdn));
		strcpy(rec->msisdn, context[i].msisdn);
		
		rec->come_time = context[i].come_time;
		memset(rec->str_come_time,'\0',sizeof(rec->str_come_time));
		strcpy(rec->str_come_time,context[i].str_come_time);
		
		rec->leave_time = context[i].leave_time;
		memset(rec->str_leave_time,'\0',sizeof(rec->str_leave_time));
		strcpy(rec->str_leave_time,context[i].str_leave_time);
		
		rec->resident_time = context[i].resident_time;	
		
		rec->user_type = context[i].user_type;	
			
		memset(rec->hlr,'\0',sizeof(rec->hlr));		
		strcpy(rec->hlr, context[i].hlr);		
		memset(rec->vlr,'\0',sizeof(rec->vlr));
		strcpy(rec->vlr, context[i].vlr);

		//当前VLR
		memset(rec->current_vlr,'\0',sizeof(rec->current_vlr));
		strcpy(rec->current_vlr,context[i].current_vlr);
		//当前vlr更新时间
		rec->current_update_time = context[i].current_update_time;
		memset(rec->str_current_update_time,'\0',sizeof(rec->str_current_update_time));
		strcpy(rec->str_current_update_time,context[i].str_current_update_time);				
		//当前VLR删除时间
		rec->current_delete_time = context[i].current_delete_time;
		//当前删除时间 微妙
		memset(rec->str_current_delete_time,'\0',sizeof(rec->str_current_delete_time));
		strcpy(rec->str_current_delete_time,context[i].str_current_delete_time);		
		//最近VLR
		memset(rec->latest_vlr,'\0',sizeof(rec->latest_vlr));
		strcpy(rec->latest_vlr,context[i].latest_vlr);
		//最近更新时间
		rec->latest_update_time = context[i].latest_update_time;
		//最近更新时间 微妙
		memset(rec->str_latest_update_time,'\0',sizeof(rec->str_latest_update_time));
		strcpy(rec->str_latest_update_time,context[i].str_latest_update_time);	
		//最近删除时间
		rec->latest_delete_time = context[i].latest_delete_time;
		//最近VLR删除时间 微妙
		memset(rec->str_latest_delete_time,'\0',sizeof(rec->str_latest_delete_time));
		strcpy(rec->str_latest_delete_time,context[i].str_latest_delete_time);				
		return 0;
	}
	return -1;
}

void PrintContext(Context *rec)
{
	struct tm *tp;
	char come_time[64], leave_time[64];
	memset(come_time, '\0', sizeof(come_time));
	tp = localtime(&(rec->come_time));
		/*
	sprintf(come_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);

memset(leave_time, '\0', sizeof(leave_time));
	tp = localtime(&(rec->leave_time));
	sprintf(leave_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);*/

	/*printf("msisdn=[%s] imsi=[%s] come_time=[%d] hlr=[%s] vlr=[%s]\n", 
			rec->msisdn, rec->imsi,rec->come_time ,rec->hlr,rec->vlr);*/ 
}

int PutToContext(char *imsi, Context *rec)
{
	int i;
	i = FindIMSI(imsi);
	if(i != -1) {
		/*memset(context[i].msisdn,'\0',sizeof(context[i].msisdn));
		strcpy(context[i].msisdn, rec->msisdn);*/				
		memset(context[i].hlr,'\0',sizeof(context[i].hlr));
		strcpy(context[i].hlr, rec->hlr);		
		memset(context[i].vlr,'\0',sizeof(context[i].vlr));		
		strcpy(context[i].vlr, rec->vlr);	
	  memset(context[i].str_come_time,'\0',sizeof(context[i].str_come_time));		
		strcpy(context[i].str_come_time, rec->str_come_time);	
				
		memset(context[i].str_leave_time,'\0',sizeof(context[i].str_leave_time));		
		strcpy(context[i].str_leave_time, rec->str_leave_time);							
		context[i].come_time = rec->come_time;
		context[i].leave_time = rec->leave_time;
		context[i].resident_time = rec->resident_time;
		context[i].user_type = rec->user_type;
		memset(context[i].current_vlr,'\0',sizeof(context[i].current_vlr));
		strcpy(context[i].current_vlr,rec->current_vlr);
		context[i].current_update_time = rec->current_update_time;	
		memset(context[i].str_current_update_time,'\0',sizeof(context[i].str_current_update_time));
		strcpy(context[i].str_current_update_time,rec->str_current_update_time);
		context[i].current_delete_time = rec->current_delete_time;					
		memset(context[i].str_current_delete_time,'\0',sizeof(context[i].str_current_delete_time));
		strcpy(context[i].str_current_delete_time,rec->str_current_delete_time);
		memset(context[i].latest_vlr,'\0',sizeof(context[i].latest_vlr));
		strcpy(context[i].latest_vlr,rec->latest_vlr);		
		context[i].latest_update_time = rec->latest_update_time;
		memset(context[i].str_latest_update_time,'\0',sizeof(context[i].str_latest_update_time));
		strcpy(context[i].str_latest_update_time,rec->str_latest_update_time);
		context[i].latest_delete_time = rec->latest_delete_time;    	
		memset(context[i].str_latest_delete_time,'\0',sizeof(context[i].str_latest_delete_time));
		strcpy(context[i].str_latest_delete_time,rec->str_latest_delete_time);
		
		return 0;
	}
	return -1;
}

int FindIMSI(char *imsi)
{
	int imsino;
	int pos,next;
	//char bcdimsi[6];
	char bcdimsi[MAX_BCD_IMSI_LEN];

	imsino = atoi(imsi+6);
	pos = imsino % (chk.context_capacity - chk.hash_tune);

	//printf("find,,,imsi=[%s],,[%d]\n",imsi,Index[pos].offset);
	//Char2BCD(imsi+4, bcdimsi, 11);
	Char2BCD(imsi, bcdimsi, 15);

	if( Index[pos].offset == -1) {
		  return -1;
	}else if( isSame(bcdimsi, Index[pos].imsi, MAX_BCD_IMSI_LEN )) {
			return Index[pos].offset;
  }else{
		 next = Index[pos].redirect;
		 //printf("next=[%d]\n",imsi,next);
		 while( next != -1 ){
		    //printf("bcdimsi=[%s],redirect[next].imsi=[%s]\n",bcdimsi,redirect[next].imsi);		 	  
		    if( isSame(bcdimsi, redirect[next].imsi, MAX_BCD_IMSI_LEN)){
				   return redirect[next].offset;
				}else{
					 next = redirect[next].redirect;
				}
		}
		return -1;
	}
	return -1;
}

int ResetIndex(char *imsi)
{
	int imsino;
	int pos,next;
	char bcdimsi[MAX_BCD_IMSI_LEN];

	imsino = atoi(imsi+6);
	pos = imsino % (chk.context_capacity - chk.hash_tune);

	Char2BCD(imsi, bcdimsi, 15);

	if( Index[pos].offset == -1) {
		  return -1;
	}else if( isSame(bcdimsi, Index[pos].imsi, MAX_BCD_IMSI_LEN )) {
		  memset(Index[pos].imsi,'\0',sizeof(Index[pos].imsi));
		  Index[pos].offset = -1 ;
			return 0;
  }else{
		 next = Index[pos].redirect;
		 while( next != -1 ){
		    if( isSame(bcdimsi, redirect[next].imsi, MAX_BCD_IMSI_LEN)){
		       memset(redirect[next].imsi,'\0',sizeof(redirect[next].imsi));
		    	 redirect[next].offset = -1 ;
				   return 0;
				}else{
					 next = redirect[next].redirect;
				}
		}
		return -1;
	}
	return -1;
}

//void *load_timer(void *arg)
int load_timer()
{
	int i, load_interval;
	//Config *cfg;
  int ret = 1;
	int pthread_id;
	//int analyze_thread_num = 0;
	char str_result[2];
	char errinfo[200];
	memset(str_result, '\0', sizeof(str_result));

	pthread_id = pthread_self();
	
	//printf("漫游输出[%d]...\n", pthread_id);

	//cfg=(Config *)Malloc(sizeof(Config));
	//ReadConfig("../etc/ssanalyze.conf", cfg);
	//load_interval = cfg->load_interval;
	//analyze_thread_num = cfg->analyze_thread_num;
	
	//printf("输出线程[%d]启动.analyze_thread_num=%d \n", pthread_id,analyze_thread_num); 
	//free(cfg);

	//while(1) {
	//	sleep(load_interval);

		//for(i=0; i<7; i++)
		//每次休眠后让数据输出到文件，并重新切换输出文件名称
		//for(i=0; i<LOAD_FILE_NUM; i++)
		for(i=0; i<chk.load_file_num; i++)
		{
			pthread_mutex_lock(&filtrate_mutex);
			ana.timeout[i]=1;
			// 输出到结果文件中 每次休眠后生成一个文件
			WriteResult(i, str_result);				
			pthread_mutex_unlock(&filtrate_mutex);
		}
		//printf("输出线程[%d] in load_timer after ana.timeout=1 \n", pthread_id); 
		
		
		/*
		//每次休眠后设置为超时输出，需要有后续进入consume处理才能输出
		for(i=0; i<LOAD_FILE_NUM; i++)
		{
			ana.timeout[i]=1;
		}
		*/
		/*update_user_resident_time();*/

		/*if(( exitflag > 0 ) && (file_read_exitflag > 0)) 	{
			memset(errinfo,'\0',sizeof(errinfo));
			sprintf(errinfo,"漫入漫出客户变动输出线程退出，请关注！");		   
			write_error_file(chk.log_file_path,"saRoamMonitor","R1001",2,errinfo);	
			pthread_exit(0);
		}*/
	//}
	
	return ret;
}

void *resident_timer(void *arg)
{
	int resident_time_interval;
	int pthread_id;
	char errinfo[200];

	pthread_id = pthread_self();
	
	printf("漫游定时输出线程[%d]启动...\n", pthread_id);

	resident_time_interval = chk.resident_time_interval;

	while(1) {
		sleep(resident_time_interval);
		//每次休眠后设置为超时输出，需要有后续进入consume处理才能输出
		
		//pthread_mutex_lock(&chk.mutex);
		update_user_resident_time();
		//pthread_mutex_unlock(&chk.mutex);

		if((exitflag>0) && (file_read_exitflag > 0)) 	{
			memset(errinfo,'\0',sizeof(errinfo));
			sprintf(errinfo,"漫入漫出客户定期输出线程退出，请关注！");		   
			write_error_file(chk.err_file_path,"saRoamMonitor","62",2,errinfo);	
			pthread_exit(0);
		}
	}
}

int update_user_resident_time()
{
	int i, ruleid;
	//time_t curr_system_time;
	//char str_curr_system_time[20];
	char str_imsi[20];
	char str_msisdn[25];
	Context rec;
	//char lac_ci_id[20];
	struct tm *tp;
	char str_result[BIG_MAXLINE];
	char str_tmp[2];
	int outflag = 0;

	//取得系统当前时间
	//memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
	//time(&curr_system_time);
	//tp = localtime(&curr_system_time);
	//sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
	//tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_curr_system_time=[%s]\n", str_curr_system_time);

	int index_num;
  memset(str_imsi, '\0', sizeof(str_imsi));	
  memset(str_msisdn, '\0', sizeof(str_msisdn));	
  
	for(i=0; i<(chk.context_capacity-chk.hash_tune); i++ ) {
		index_num = Index[i].offset;
		if(index_num != -1){
			// 取得输出字符串
			BCD2Char(Index[i].imsi, str_imsi, 15);				
			GetFromContext(str_imsi, &rec);
			//printf("user_type=%d\n",rec.user_type);
			if(rec.user_type == 1){
				// 写输出文件
				memset(str_tmp, '\0', sizeof(str_tmp));
        memset(str_msisdn, '\0', sizeof(str_msisdn));	
        strcpy(str_msisdn,rec.msisdn);				
				strncpy(str_tmp, (rec.msisdn)+10, 1);
				ruleid = (atoi(str_tmp))%chk.load_file_num;
							
				// 更新停留时间20100401
				//rec.resident_time = (ana.event_time_begin[ruleid] - context[index_num].come_time + 3600)/60;			  
        if(rec.current_delete_time > 0 
        	  && abs(ana.event_time_begin[ruleid]-rec.current_delete_time) > chk.signal_roam_judge_timing){
        	  rec.leave_time = rec.current_delete_time;
        	  memset(rec.str_leave_time,'\0',sizeof(rec.str_leave_time));
        	  strcpy(rec.str_leave_time,rec.str_current_delete_time);
        	  memset(rec.vlr,'\0',sizeof(rec.vlr));
        	  strcpy(rec.vlr,rec.current_vlr);
        	  rec.resident_time = rec.leave_time - rec.come_time;
        	  outflag = 1;
        }else{
				    rec.resident_time = ana.event_time_begin[ruleid] - rec.come_time + 3600;	        	
        }
				memset(str_result, '\0', sizeof(str_result));
				GetResultStr(&rec, 0, str_result);
			
				pthread_mutex_lock(&filtrate_mutex);
				//memset(str_tmp, '\0', sizeof(str_tmp));
				//strncpy(str_tmp, (rec.msisdn)+10, 1);
				//ruleid = (atoi(str_tmp))%chk.load_file_num;
				WriteResult(ruleid, str_result);
				pthread_mutex_unlock(&filtrate_mutex);
				
				if( outflag == 1){  //判断离开
					 rec.come_time = 0;
					 memset(rec.str_come_time,'\0',sizeof(rec.str_come_time));
					 rec.leave_time = 0;
					 rec.resident_time =0;
					 memset(rec.str_leave_time,'\0',sizeof(rec.str_leave_time));
					 memset(rec.hlr,'\0',sizeof(rec.hlr));
					 memset(rec.vlr,'\0',sizeof(rec.vlr));
					 rec.user_type = 0;
					 memset(rec.current_vlr,'\0',sizeof(rec.current_vlr));
					 rec.current_update_time =0;
					 memset(rec.str_current_update_time,'\0',sizeof(rec.str_current_update_time));
					 rec.current_delete_time = 0;
					 memset(rec.str_current_delete_time,'\0',sizeof(rec.str_current_delete_time));
					 memset(rec.latest_vlr,'\0',sizeof(rec.latest_vlr));
					 rec.latest_update_time = 0;
					 memset(rec.str_latest_update_time,'\0',sizeof(rec.str_latest_update_time));
					 rec.latest_delete_time = 0;
					 memset(rec.str_latest_delete_time,'\0',sizeof(rec.str_latest_delete_time));
					 PutToContext(str_imsi, &rec);	
					 outflag = 0;
				}
			}
		}
	}
  
	for(i=0; i<chk.redirect_capacity; i++ ) {
		index_num = redirect[i].offset;
		if(index_num != -1) {	
			BCD2Char(redirect[i].imsi, str_imsi, 15);
			GetFromContext(str_imsi, &rec);
			//printf("user_type=%d\n",rec.user_type);
			if(rec.user_type == 1){
				// 写输出文件
				memset(str_tmp, '\0', sizeof(str_tmp));
        memset(str_msisdn, '\0', sizeof(str_msisdn));	
        strcpy(str_msisdn,rec.msisdn);
			  strncpy(str_tmp, (rec.msisdn)+10, 1);
			  ruleid = (atoi(str_tmp))%chk.load_file_num;
			  			
			  // 更新停留时间 当前时间-进入时间
			  //rec.resident_time = (ana.event_time_begin[ruleid] - context[index_num].come_time + 3600)/60;
        if(rec.current_delete_time > 0 
        	  && abs(ana.event_time_begin[ruleid]-rec.current_delete_time) > chk.signal_roam_judge_timing){
        	  rec.leave_time = rec.current_delete_time;
        	  memset(rec.str_leave_time,'\0',sizeof(rec.str_leave_time));
        	  strcpy(rec.str_leave_time,rec.str_current_delete_time);
        	  memset(rec.vlr,'\0',sizeof(rec.vlr));
        	  strcpy(rec.vlr,rec.current_vlr);
        	  rec.resident_time = rec.leave_time - rec.come_time;
        	  outflag = 1;
        }else{
				    rec.resident_time = ana.event_time_begin[ruleid] - rec.come_time + 3600;	        	
        }	
			  		  		
			  memset(str_result, '\0', sizeof(str_result));
			  GetResultStr(&rec, 0, str_result);
			  
			  pthread_mutex_lock(&filtrate_mutex);
			  //memset(str_tmp, '\0', sizeof(str_tmp));
			  //strncpy(str_tmp, (rec.msisdn)+10, 1);
			  //ruleid = (atoi(str_tmp))%chk.load_file_num;
			  WriteResult(ruleid, str_result);
			  pthread_mutex_unlock(&filtrate_mutex);
			  if( outflag == 1){  //判断离开
					 rec.come_time = 0;
					 memset(rec.str_come_time,'\0',sizeof(rec.str_come_time));
					 rec.leave_time = 0;
					 rec.resident_time =0;
					 memset(rec.str_leave_time,'\0',sizeof(rec.str_leave_time));
					 memset(rec.hlr,'\0',sizeof(rec.hlr));
					 memset(rec.vlr,'\0',sizeof(rec.vlr));
					 rec.user_type = 0;
					 memset(rec.current_vlr,'\0',sizeof(rec.current_vlr));
					 rec.current_update_time =0;
					 memset(rec.str_current_update_time,'\0',sizeof(rec.str_current_update_time));
					 rec.current_delete_time = 0;
					 memset(rec.str_current_delete_time,'\0',sizeof(rec.str_current_delete_time));
					 memset(rec.latest_vlr,'\0',sizeof(rec.latest_vlr));
					 rec.latest_update_time = 0;
					 memset(rec.str_latest_update_time,'\0',sizeof(rec.str_latest_update_time));
					 rec.latest_delete_time = 0;
					 memset(rec.str_latest_delete_time,'\0',sizeof(rec.str_latest_delete_time));
					 PutToContext(str_imsi, &rec);	
					 outflag = 0;
				}
			}						
		}
	}  

	return 1;
}
