
#include "sspublic.h"
#include "sscontext.h"
//#include "ssanalyze.h"

#ifdef _ORACLE_
#include "ssoracle.h"
#endif /* _ORACLE */
#ifdef _DB2_
#include "ssdb2.h"
#endif /* _DB2_ */

//map<string, InfoStat> m_Number_Info;


BCDContext	*context;
BCDIndex	*Index;
BCDIndex	*redirect;
Config *cfg;
	
void *init_timer(void *arg)
{
	time_t t0,t1;
	struct tm *t;
	int sleep_interval;

	cfg = (Config *)Malloc(sizeof(Config));
	ReadConfig("../../etc/c/smLocalContext.conf", cfg);
			
	while(1)
	{
		t1 = time(&t0);

		t0 = t1;

		if(chk.init_context_period == 1)
		{
			t1+=24*3600;
    	
			t=localtime(&t1);
			t->tm_hour=chk.init_context_hour;
			t->tm_min=chk.init_context_min;
			t->tm_sec=0;
		} 
		else if (chk.init_context_period == 2)
		{
			t=localtime(&t1);
			
			t->tm_hour=chk.init_context_hour;
			t->tm_min=chk.init_context_min;
			t->tm_sec=0;	
								
			if(t->tm_mday > chk.init_context_day)
			{
				t->tm_mon=t->tm_mon+1;	
				t->tm_mday=chk.init_context_day;							
			}			
		}		
		else 
		{
			printf ("init period error，period:%d\n",chk.init_context_period);
			exit(-1);
		}
		
		t1 = mktime(t);	
		printf("t->tm_mon=%d,t->tm_mday=%d,chk.init_context_day:%d t->tm_mon\n",t->tm_mon,t->tm_mday,chk.init_context_day);	
				
		sleep_interval = t1 -t0;
		sleep(t1-t0);
		//测试使用
		//sleep(120); 
		
		//上下文初始化需要全程锁定，完成后释放锁
		pthread_mutex_lock(&chk.mutex);
		
		time_t begin_time, end_time;
		char str_begin_time[20], str_end_time[20];
		memset(str_begin_time, '\0', sizeof(str_begin_time));
		begin_time = get_system_time(str_begin_time);
		printf("初始化上下文信息开始 str_begin_time=[%s]...\n", str_begin_time);
		
		InitLocalContext();
		
		memset(str_end_time, '\0', sizeof(str_end_time));
		end_time = get_system_time(str_end_time);
		printf("初始化上下文信息结束 str_end_time=[%s]\n\n", str_end_time);

		pthread_mutex_unlock(&chk.mutex);		
	}	
	
}

void *backup_timer(void *arg)
{
	int fd;
	time_t sys_time;
	char str_sys_time[20];
	
	char tmp[500];

	while(1) 
	{
		sleep(chk.backup_context_interval);

		// 取得系统当前时间
		memset(str_sys_time, '\0', sizeof(str_sys_time));
		sys_time = get_system_time_2(str_sys_time);
		//printf("str_sys_time=[%s]\n", str_sys_time);

		memset(tmp, '\0', sizeof(tmp));
		sprintf(tmp, "%s.%s", BACKUP_FILE_PREFIX, str_sys_time+4);

		//BackupContext("context.txt");
		//BackupContext(tmp);

		char str_file_name[200];
		memset(str_file_name, '\0', sizeof(str_file_name));
		strcpy(str_file_name, "../bin/exitflag");
		//strcpy(str_file_name, "exitflag");
		
		//printf("backup_timer本轮启动\n");
		fd=open(str_file_name, O_RDONLY);
		if(fd>0) {
			exitflag=1;
			close(fd);
			remove(str_file_name);
			//printf("1111111111111111111111111111111111\n");
			pthread_exit(0);
		}
	}
	return (NULL);
}

void *log_timer(void *arg)
{
	int fd;
	time_t sys_time;
	char str_sys_time[20];	
	char filename[200],rfilename[200];
	char errinfo[200];	
			
	while(1) 
	{
		sleep(chk.log_interval);

		// 取得系统当前时间
		memset(str_sys_time, '\0', sizeof(str_sys_time));
		sys_time = get_system_time_2(str_sys_time);
	  memset(filename, 0, sizeof(filename));
	  memset(rfilename, 0, sizeof(rfilename));
		sprintf(filename,"%ssmLocalContext.tmp",chk.log_file_path);
		sprintf(rfilename,"%ssmLocalContext_%d_%s.del",chk.log_file_path,getpid(),str_sys_time);		
		fd=open(filename, O_RDONLY);
		if(fd>0) {
		   pthread_mutex_lock(&pthread_logfile_mutex);
		   rename(filename,rfilename);
		   pthread_mutex_unlock(&pthread_logfile_mutex);
 		  close(fd);
		}
		
		if((exitflag>0) && (file_read_exitflag > 0)) 	{
		  printf("客户日志输出线程退出\n");
			memset(errinfo,'\0',sizeof(errinfo));
			sprintf(errinfo,"客户日志输出线程退出，请关注！");		   
			write_error_file(chk.err_file_path,"smLocalContext","65",2,errinfo);	
			pthread_exit(0);
		}
	}
	return (NULL);
}

int InitContext(void)
{
	//int i;

	//pthread_mutex_lock(&chk.mutex);

	/*
	for(i=0; i<chk.context_capacity-chk.hash_tune; i++)
	{
		Index[i].offset=Index[i].redirect= -1;
	}
	
	for(i=0; i<chk.redirect_capacity; i++)
	{            
		redirect[i].offset=redirect[i].redirect=-1;
	}
	*/
		
	/*
	#ifdef _DB2_
	
	chk.context_capacity_used = read_context_file(chk.filename);
	#endif //_DB2_ 

	#ifdef _ORACLE_
	chk.context_capacity_used = read_context(chk.table_name, chk.select_cond);
	#endif //_ORACLE_ 	
	
	*/

	//chk.context_capacity_used =; 
	read_context_file(chk.filename);
		
	//printf("in InitContext read_context ok \n ");
	//pthread_mutex_unlock(&chk.mutex);
	
	return 0;
}


int InitLocalContext(void)
{
	int i, ruleid;
	time_t curr_system_time;
	char str_curr_system_time[20];

	char str_imsi[20];
	memset(str_imsi, '\0', sizeof(str_imsi));

	Context rec;
	struct tm *tp;

	char str_result[BIG_MAXLINE];

	char str_tmp[2];
	int index_num;
	int ret;
		
	//先输出上下文信息，同时清空上下文
	printf("in InitLocalContext start \n ");

	/*
	//配置为读取imsi与msisdn表数据时，则需要初始化读取
	if(chk.imsi_msisdn_flag == 0)	
	{
			ret = connect_db(cfg->db_name, cfg->db_user, cfg->db_passwd);	
			//连接数据库，连接不上则当天不做初始化
			if (ret == -1 ) {
          return -1;
			}
	}
	*/
	
	// 取得系统当前时间
	memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
	time(&curr_system_time);
	tp = localtime(&curr_system_time);
	sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	printf("in InitLocalContext init %s\n ",str_curr_system_time);	
		
	//初始化上下文
	for(i=0; i<(chk.context_capacity-chk.hash_tune); i++ ) 
	{
		index_num = Index[i].offset;
		if(index_num != -1) 
		{
				//初始化上下文
				memset(context[index_num].msisdn, '\0', sizeof(context[index_num].msisdn));
				memset(context[index_num].local_prov_flag, '\0', sizeof(context[index_num].local_prov_flag));
				memset(context[index_num].prov_code, '\0', sizeof(context[index_num].prov_code));
				memset(context[index_num].city_code, '\0', sizeof(context[index_num].city_code));																								
		}
	}
  
  printf("in index context ok \n ");
  
	for(i=0; i<chk.redirect_capacity; i++ ) 
	{
		index_num = redirect[i].offset;
		if(index_num != -1) 
		{
				//初始化上下文
				memset(context[index_num].msisdn, '\0', sizeof(context[index_num].msisdn));
				memset(context[index_num].local_prov_flag, '\0', sizeof(context[index_num].local_prov_flag));
				memset(context[index_num].prov_code, '\0', sizeof(context[index_num].prov_code));
				memset(context[index_num].city_code, '\0', sizeof(context[index_num].city_code));							
		}
	}
	
	printf("in redirect context ok \n ");
	
	//再初始化索引
	for(i=0; i<chk.context_capacity-chk.hash_tune; i++)
	{
		memset(Index[i].imsi, '\0', sizeof(Index[i].imsi));
		Index[i].offset=Index[i].redirect= -1;
	}
	
	for(i=0; i<chk.redirect_capacity; i++)
	{ 
		memset(Index[i].imsi, '\0', sizeof(Index[i].imsi));           
		redirect[i].offset=redirect[i].redirect=-1;
	}

  //上下文已经使用大小和重定向清零
  chk.context_capacity_used = 0; 
  chk.redirect_capacity = 0;
  		
	printf("in InitLocalContext index ok \n ");
	
	
	//配置为读取imsi与msisdn表数据时，则需要初始化读取
	if(chk.imsi_msisdn_flag == 0)	
	{
		/*
		#ifdef _DB2_
		export_file();
		chk.context_capacity_used = read_context_file(chk.filename);
		#endif //_DB2_ 
  	
		#ifdef _ORACLE_
		chk.context_capacity_used = read_context(chk.table_name, chk.select_cond);
		#endif //_ORACLE_ 	
	
		//读取完数据后，即关闭数据库连接
  	close_db();	
  	*/

	  //chk.context_capacity_used = 
	  read_context_file(chk.filename);
	    	
		printf("in InitLocalContext load ok \n ");  	
	}

	return 0;
}


int InsertContext(char *imsi,char *msisdn)
{
	int pos,next;
	int ci,rj=0;
	int imsino;
	char bcdimsi[MAX_BCD_IMSI_LEN];
	
	char imsi_cond[16];
	char msisdn_cond[16];
	ci=rj=0;
	
	memset(imsi_cond, '\0', sizeof(imsi_cond));	
	memset(msisdn_cond, '\0', sizeof(msisdn_cond));	
	
	strcpy(imsi_cond, imsi);
	strcpy(msisdn_cond, msisdn);
	
	ci = chk.context_capacity_used;
	rj = chk.redirect_capacity;
	
  memcpy(context[ci].msisdn,msisdn_cond, strlen(msisdn_cond));
  
	imsino = atoi(imsi_cond+6);
	pos = imsino % (chk.context_capacity-chk.hash_tune);
  //cout <<"imsino="<<imsino <<" pos=" <<pos <<endl;
  
  Char2BCD(imsi_cond,  bcdimsi, 15);
  
	if( Index[pos].offset == -1) {
			Index[pos].offset = ci;
			//printf("imsi=%s Index[%d].offset=%d\n",imsi,pos,ci);
			memcpy(Index[pos].imsi,bcdimsi, MAX_BCD_IMSI_LEN);
	}
	else {
			next=Index[pos].redirect;
    	
			if(next == -1)
			{
				Index[pos].redirect = rj;
				//printf("Index[%d].redirect = %d next=%d\n",pos,rj,next);
			}
			else
			{
				while(redirect[next].redirect != -1) {
					next=redirect[next].redirect;
				}
				redirect[next].redirect=rj;
				//printf("redirect[%d].redirect=%d pos=%d\n",next,rj,pos);
			}
			
  		//因后面连续分配内存空间可能因连续内存空间不足而失败，
  		//故而预先分配和改为和上下文一样数量的重定向索引内存空间，启动时一次分配完			
			//重定向数量加1，
			chk.redirect_capacity++;
			//redirect = (BCDIndex *)realloc(redirect,sizeof(BCDIndex)*chk.redirect_capacity);
			
			memcpy(redirect[rj].imsi,bcdimsi, MAX_BCD_IMSI_LEN);
			redirect[rj].offset = ci;
			redirect[rj].redirect = -1;
			//printf("imsi=%s redirect[%d].offset=%d,pos=%d\n",imsi,rj,ci,pos);		
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
			strcpy(rec.imsi, word[1]);
			strcpy(rec.last_cell, word[2]);
			rec.mobile_status = word[3][0];
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

			memcpy(rec.last_action_type, word[13], strlen(word[13]));

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
	int num;
	char imsi[16], tmp[128];

	FileBuff fb;
	Context rec;

	fb.num=0;
	fb.from=0;
	/*bzero(fb.buf,FBUFFSIZE);*/
	memset(fb.buf, '\0', FBUFFSIZE);

	strcpy(tmp, tofile);
	strcat(tmp, ".backup");
	rename(tofile, tmp);

	fd=open(tofile, O_WRONLY|O_CREAT, 0644);
	if(fd<0) {
		printf("Can't open file:%s,backup context failure\n",tofile);
		return -1;
	}

	num=0;
	strcpy(imsi,"4600");

	pthread_mutex_lock(&chk.mutex);

	for(i=0; i<(chk.context_capacity-chk.hash_tune); i++ ) 
	{
		//printf("wld i[%d]\n", i);
		if(Index[i].offset != -1) {
			BCD2Char( Index[i].imsi, imsi+4, 11);
			WriteContextBuf(Index[i].offset, fd, imsi, &fb);
		}
	}

	for(i=0; i<chk.redirect_capacity; i++ ) 
	{
		if(redirect[i].offset != -1) {
			BCD2Char( redirect[i].imsi, imsi+4, 11);
			WriteContextBuf(redirect[i].offset, fd, imsi, &fb);
		}
	}

	pthread_mutex_unlock(&chk.mutex);

	
	if(num>0)  write(fd, fb.buf, fb.num);
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
	if(i != -1) 
	{
		strcpy(rec->msisdn, context[i].msisdn);
		strcpy(rec->local_prov_flag, context[i].local_prov_flag);	
		strcpy(rec->prov_code, context[i].prov_code);		
		strcpy(rec->city_code, context[i].city_code);							
		//printf("imsi=%s,rec->msisdn=%s \n",imsi,rec->msisdn);
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
	sprintf(come_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);

	memset(leave_time, '\0', sizeof(leave_time));
	tp = localtime(&(rec->leave_time));
	sprintf(leave_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);

	/*
	printf("msisdn=[%s] imsi=[%s] last_cell=[%0.11s] mobile_status=[%c] smo_sms_counts=[%d] calling_call_counts=[%d] calling_call_duration=[%d] smt_sms_counts=[%d] called_call_counts=[%d] called_call_duration=[%d] come_time=[%0.19s] leave_time=[%0.19s]  resident_time=[%d] other_numbers=[%s] calling_other_party_area=[%s] called_other_party_area=[%s] last_action_type=[%s]\n", 
			rec->msisdn, rec->imsi, rec->last_cell, rec->mobile_status, 
			rec->smo_sms_counts, rec->calling_call_counts, rec->calling_call_duration,
			rec->smt_sms_counts, rec->called_call_counts, rec->called_call_duration,
			come_time, leave_time, rec->resident_time,
			rec->other_numbers, rec->calling_other_party_area, rec->called_other_party_area,
			rec->last_action_type);
 */
 
	printf("msisdn=[%s] imsi=[%s] last_cell=[%s] mobile_status=[%c] smo_sms_counts=[%d] calling_call_counts=[%d] calling_call_duration=[%d] smt_sms_counts=[%d] called_call_counts=[%d] called_call_duration=[%d] come_time=[%0.19s] leave_time=[%0.19s]  resident_time=[%d] other_numbers=[%s] calling_other_party_area=[%s] called_other_party_area=[%s] last_action_type=[%s]\n", 
			rec->msisdn, rec->imsi, rec->last_cell, rec->mobile_status, 
			rec->smo_sms_counts, rec->calling_call_counts, rec->calling_call_duration,
			rec->smt_sms_counts, rec->called_call_counts, rec->called_call_duration,
			come_time, leave_time, rec->resident_time,
			rec->other_numbers, rec->calling_other_party_area, rec->called_other_party_area,
			rec->last_action_type);

	/*
	printf("imsi=[%s] other_numbers=[%s] last_action_type=[%s]\n", 
			rec->imsi, rec->other_numbers, rec->last_action_type);
	*/
}

int PutToContext(char *imsi, Context *rec)
{
	int i;
	char str_tmp[MAXLINE], str_tmp_2[MAXLINE];
	char* p_field;

	char* p_other_numbers=NULL;

	i = FindIMSI(imsi);
	if(i != -1) {
		strcpy(context[i].local_prov_flag, rec->local_prov_flag);
		strcpy(context[i].prov_code, rec->prov_code);
		strcpy(context[i].city_code, rec->city_code);
		return 0;
	}
	return -1;
}


int FindIMSI(char *imsi)
{
	int imsino;
	int pos,next;
	char bcdimsi[MAX_BCD_IMSI_LEN];

	imsino = atoi(imsi+6);

	pos = imsino % (chk.context_capacity - chk.hash_tune);

	Char2BCD(imsi, bcdimsi, 15);

  //printf("in FindIMSI,imsi=%s,bcdimsi=%s,pos=%d,Index[pos].imsi=%s \n",imsi,bcdimsi,pos,Index[pos].imsi);
	if( Index[pos].offset == -1) return -1;
	else if( isSame(bcdimsi, Index[pos].imsi, MAX_BCD_IMSI_LEN ))	return Index[pos].offset;
	else
	{
		next = Index[pos].redirect;
		while( next != -1 )
		{
			if( isSame(bcdimsi, redirect[next].imsi, MAX_BCD_IMSI_LEN))
				return redirect[next].offset;
			else next = redirect[next].redirect;
		}
		return -1;
	}
	return -1;
}


void *load_timer(void *arg)
{
	int i, load_interval;
	Config *cfg;

	int pthread_id;
	//int analyze_thread_num = 0;
	char str_result[2];
	memset(str_result, '\0', sizeof(str_result));

	pthread_id = pthread_self();
	
	printf("输出线程[%d]启动...\n", pthread_id);


	cfg=(Config *)Malloc(sizeof(Config));
	ReadConfig("../../etc/c/smLocalContext.conf", cfg);
	load_interval = cfg->load_interval;
	//analyze_thread_num = cfg->analyze_thread_num;
	
	//printf("输出线程[%d]启动.analyze_thread_num=%d \n", pthread_id,analyze_thread_num); 
	free(cfg);

	while(1) {
		sleep(load_interval);

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

		if((exitflag>0) && (file_read_exitflag > 0)) 	
		{
			pthread_exit(0);
		}
	}
}


int update_user_resident_time()
{
	int i, ruleid;
	time_t curr_system_time;
	char str_curr_system_time[20];

	char str_imsi[20];
	memset(str_imsi, '\0', sizeof(str_imsi));
	strcpy(str_imsi,"4600");

	Context rec;

	char lac_ci_id[20];

	struct tm *tp;

	char str_result[BIG_MAXLINE];

	char str_tmp[2];

	// 考虑性能问题，此处不加锁
	//pthread_mutex_lock(&chk.mutex);

	// 取得系统当前时间
	memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
	time(&curr_system_time);
	tp = localtime(&curr_system_time);
	sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_curr_system_time=[%s]\n", str_curr_system_time);

  /* xiamw 20100118
	unsigned int index_num;
	for(i=0; i<(chk.context_capacity-chk.hash_tune); i++ ) 
	{
		//printf("wld i=[%d]\n", i);
		index_num = Index[i].offset;
		if(index_num != -1) 
		{
			// 更新停留时间 当前时间-进入时间
			context[index_num].resident_time = (curr_system_time - context[index_num].come_time)/60;
				//printf("wld i=[%d]\n", i);
				//printf("Index 0000 resident_time=[%d]\n", context[index_num].resident_time);
			if((context[index_num].resident_time) < (chk.resident_time_raft))
			{
				--//
				char tmp[20];
				memset(tmp, '\0', sizeof(tmp));
				tp = localtime(&(context[index_num].come_time));
				sprintf(tmp, "%4d-%02d-%02d %02d:%02d:%02d",
				tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
				printf("tmp=[%s]\n", tmp);
				--//

				// 取得输出字符串
				BCD2Char(Index[i].imsi, str_imsi+4, 11);
				pthread_mutex_lock(&chk.mutex);
				GetFromContext(str_imsi, &rec);
				pthread_mutex_unlock(&chk.mutex);
				//printf("Index 1111 str_imsi=[%s]\n", str_imsi);
				pthread_mutex_lock(&chk.mutex);
				memset(str_result, '\0', sizeof(str_result));
				GetResultStr(&rec, 0, str_result);
				pthread_mutex_unlock(&chk.mutex);
				//printf("Index 2222 str_result=[%s]\n", str_result);


				// 判断当前用户对应的小区信息是否在逻辑区表中
				pthread_mutex_lock(&filtrate_mutex);
				memset(lac_ci_id, '\0', sizeof(lac_ci_id));
				strncpy(lac_ci_id, rec.last_cell, 11);
				//printf("lac_ci_id=[%s]\n", lac_ci_id);
				int res_physical_area = 0;
				res_physical_area = find_physical_area(lac_ci_id);
    			if(res_physical_area != 0)
   				{
					// 写输出文件
					memset(str_tmp, '\0', sizeof(str_tmp));
					//strncpy(str_tmp, str_imsi+14, 1);
					strncpy(str_tmp, (rec.msisdn)+10, 1);
					//ruleid = (atoi(str_tmp))%7;
					ruleid = (atoi(str_tmp))%LOAD_FILE_NUM;
					//printf("aaaa str_tmp=[%s] ruleid=[%d]\n", str_tmp, ruleid);
					WriteResult(ruleid, str_result);
				}
				pthread_mutex_unlock(&filtrate_mutex);
			}
		}
	}
  
	for(i=0; i<chk.redirect_capacity; i++ ) 
	{
		index_num = redirect[i].offset;
		if(index_num != -1) 
		{
			// 更新停留时间 当前时间-进入时间
			context[index_num].resident_time = (curr_system_time - context[index_num].come_time)/60;
			
			if((context[index_num].resident_time) < (chk.resident_time_raft))
			{
				// 取得输出字符串
				//printf("redirect 0000 resident_time=[%d] come_time=[%d]\n", context[index_num].resident_time, context[index_num].come_time);
				BCD2Char(redirect[i].imsi, str_imsi+4, 11);
				pthread_mutex_lock(&chk.mutex);
				GetFromContext(str_imsi, &rec);
				pthread_mutex_unlock(&chk.mutex);
				//printf("redirect 1111 str_imsi=[%s]\n", str_imsi);
				pthread_mutex_lock(&chk.mutex);
				memset(str_result, '\0', sizeof(str_result));
				GetResultStr(&rec, 0, str_result);
				pthread_mutex_unlock(&chk.mutex);
				//printf("redirect 1111 str_result=[%s]\n", str_result);

				// 判断当前用户对应的小区信息是否在逻辑区表中
				pthread_mutex_lock(&filtrate_mutex);
				memset(lac_ci_id, '\0', sizeof(lac_ci_id));
				strncpy(lac_ci_id, rec.last_cell, 11);
				//printf("lac_ci_id=[%s]\n", lac_ci_id);
				int res_physical_area = 0;
				res_physical_area = find_physical_area(lac_ci_id);
    			if(res_physical_area != 0)
   				{
					// 写输出文件
					memset(str_tmp, '\0', sizeof(str_tmp));
					//strncpy(str_tmp, str_imsi+14, 1);
					strncpy(str_tmp, (rec.msisdn)+10, 1);
					//ruleid = (atoi(str_tmp))%7;
					ruleid = (atoi(str_tmp))%LOAD_FILE_NUM;
					//printf("aaaa str_tmp=[%s] ruleid=[%d]\n", str_tmp, ruleid);
					WriteResult(ruleid, str_result);
				}
				pthread_mutex_unlock(&filtrate_mutex);
			}
		}
	}
	
  */
  
	// 考虑性能问题，此处不加锁
	//pthread_mutex_unlock(&chk.mutex);

	return 1;
}


int read_context_file(char *map_file_name)
{
	int pos,next;
	int ci,rj,conflict=0;
	int imsino;
	/*char bcdimsi[6];20110419*/
	char bcdimsi[MAX_BCD_IMSI_LEN];
	
	int curr_i=0; 

	char msisdn_cond[16];
	char imsi_cond[16];
	char city_code[MAX_CITY_CODE_LEN];
			
	int	fd_map;
	char line[40];
	FileBuff fb_map;
	char buff_map[300];
	
	int ret;
	char *word[50];
	
	int len[50];
	
	fb_map.num=0;
	fb_map.from=0;
	int num=1;

	ci=rj=0;
	
		// 处理文件中的每条映射数据
	fd_map=open(map_file_name, O_RDONLY);
	
	while(num>0)
	{
		// 取得文件中的每条记录
		num = ReadLine(fd_map, &fb_map, line, MAXLINE);	// 当num==0时，表示已到达文件尾或是无可读取的数据
		
		if( num > 0 ) 
		{
			memset(word, '\0', sizeof(word));						
			ret=Split(line, ',', 50, word, len);
			
			memset(imsi_cond, '\0', sizeof(imsi_cond));
			strcpy(imsi_cond, word[0]);
			//LTrim(imsi_cond, ' ');
			//RTrim(imsi_cond, ' ');
			
			memset(msisdn_cond, '\0', sizeof(msisdn_cond));
			strcpy(msisdn_cond, word[1]);
			//LTrim(msisdn_cond, ' ');
			//RTrim(msisdn_cond, ' ');

			memset(city_code, '\0', sizeof(city_code));
			strcpy(city_code, word[2]);
			    	
			//Char2BCD(msisdn_cond, context[ci].msisdn, 11); MAX_BCD_MSISDN_NUMBERS
    	memcpy(context[ci].msisdn,msisdn_cond, strlen(msisdn_cond));
    	strcpy(context[ci].city_code, city_code);
    	strcpy(context[ci].local_prov_flag, "1");
    	strcpy(context[ci].prov_code, chk.local_prov_code); 
    					    	
			imsino = atoi(imsi_cond+6);
			pos = imsino % (chk.context_capacity-chk.hash_tune);
    	
			/*Char2BCD(imsi_cond+4,  bcdimsi, 11);20110419*/
			Char2BCD(imsi_cond,  bcdimsi, 15);
    	
			if( Index[pos].offset == -1) {
				Index[pos].offset = ci;
				/*bcopy(bcdimsi, Index[pos].imsi, 6);20090326*/
				/*memcpy(Index[pos].imsi,bcdimsi, 6);*/
				memcpy(Index[pos].imsi,bcdimsi, MAX_BCD_IMSI_LEN);
			}
			else {
				next=Index[pos].redirect;
				if(next == -1)
				{
					Index[pos].redirect = rj;
					/*bcopy(bcdimsi, redirect[rj].imsi, 6);20090326*/
					/*memcpy(redirect[rj].imsi,bcdimsi, 6);*/
					memcpy(redirect[rj].imsi,bcdimsi, MAX_BCD_IMSI_LEN);
					redirect[rj].offset = ci;
				}
				else
				{
					while(  redirect[next].redirect != -1) {
						next=redirect[next].redirect;
					}
					redirect[next].redirect=rj;
					/*bcopy(bcdimsi, redirect[rj].imsi, 6);20090326*/
					/*memcpy(redirect[rj].imsi,bcdimsi, 6);*/
					memcpy(redirect[rj].imsi,bcdimsi, MAX_BCD_IMSI_LEN);
					redirect[rj].offset=ci;
				}
				rj++;
			}
			ci++;
			
			
			if(curr_i%100000 == 0)
			{
				printf("加载 curr_i=[%d]条\n", curr_i);
			}
			
			curr_i++;
		}
	}

  printf("共加载 curr_i=[%d]条 rj=[%d] \n", curr_i,rj);
	close(fd_map);
	
	chk.redirect_capacity=rj;
  chk.context_capacity_used =	ci;	
	
	return ci;
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
	
	// 处理文件中的每条映射数据
	fd_map=open(map_file_name, O_RDONLY);
	
	//printf("map_file_name=%s\n",map_file_name);
			
	while(num>0)
	{
		// 取得文件中的每条记录
		num = ReadLine(fd_map, &fb_map, line, MAXLINE);	// 当num==0时，表示已到达文件尾或是无可读取的数据

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
				printf("初始化 curr_i=[%d]条\n", curr_i);
			}
							
			curr_i++;
			//printf("after curr_i++; \n");
		
		}
	}

	close(fd_map);


	return rj;
}	


int export_file(void)
{
	
	char buff[300];
  char sqlstring[100];
			
	#ifdef _DB2_
				
			printf("开始删除 imsi_msisdn_map.txt \n");
			memset(buff, 0, sizeof(buff));
			strcpy(buff, "rm -fr imsi_msisdn_map.txt");
			printf("buff = [%s]\n", buff);
			system(buff);
			printf("开始导出 imsi_msisdn_map.txt \n");
			
			//memset(filename, 0, sizeof(chk.filename));
			//strcpy(filename, "imsi_msisdn_map.txt");
			
			memset(sqlstring, 0, sizeof(sqlstring));
			strcpy(sqlstring, "select imsi,msisdn,city_code from ");
			strcat(sqlstring, chk.table_name);
			
			ret = export_data (sqlstring, chk.filename);
			printf("导出imsi_msisdn_map ret=%d \n",ret);
			
			memset(buff, 0, sizeof(buff));
			strcpy(buff, "sed s/\\\"//g imsi_msisdn_map.txt > imsi_msisdn_map.txt.tmp");
			printf("buff = [%s]\n", buff);
			system(buff);
			
			memset(buff, 0, sizeof(buff));
			strcpy(buff, "mv  imsi_msisdn_map.txt.tmp imsi_msisdn_map.txt");
			printf("buff = [%s]\n", buff);
			system(buff);
	
	#endif //_DB2_ 
	
	return 0;
}
