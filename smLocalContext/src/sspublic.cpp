#include "sspublic.h"
extern char **environ;


int Discard(char *line,int flds) 
{
	int i=0;
	char dest[MAXLINE];
	char *word[50];
	int  len[50];
	int  num;


	strcpy(dest, line);
	num = Split(dest, ',',MAXLINE, word, len);


	if(num != flds ) return 1;

	return 0;
}

int PutLine(char *line,  LineBuff *lb)
{
	int plen;
	int i,len;

	len=strlen(line);
	//add by chengxc
	if (len > MAXLINE) 
   {
     printf("len=%d,line=%s \n",len,line);
   }

	if(lb->empty >= len)
	{
		plen= LBSIZE - lb->to;
		if(plen<len)
		{
			for(i=0; i<plen; i++)
				lb->buf[lb->to+i]=line[i];

			for(i=0; i<len-plen; i++)
				lb->buf[i]=line[plen+i];

			lb->to = len-plen;
		}
		else {
			/*bcopy(line, lb->buf+lb->to, len);*/
			memcpy(lb->buf+lb->to, line, len);
			lb->to = (lb->to+len)%LBSIZE;
		}
		lb->empty -= len;
		lb->lines++;

		return len;
	}
	return -1;
}

int GetLine(LineBuff *lb, char *line )
{
	int i,j,start,num;

	if(lb->lines > 0)
	{
		start = lb->from;
		for(i=start; i<LBSIZE; i++)
		{
			line[i-start] = lb->buf[i];
			if(lb->buf[i] == '\n')
			{
				num = i-start+1;
				lb->from = (lb->from+num)%LBSIZE;
				lb->empty += num;
				lb->lines --;

				return num;
			}
		}

		for(j=0; j<start; j++)
		{
			line[i-start+j] = lb->buf[j];
			if(lb->buf[j] == '\n' )
			{
				num = i-start+j+1;
				lb->from = j+1;
				lb->empty += num;
				lb->lines --;

				return num;
			}
		}
	}
	return -1;
}


int Split(char *line, char ch,int maxw, char *word[], int len[])
{
	int i,j,num;
	char lastch;
	int lasti;

	num=strlen(line);

	lastch='\0';
	lasti=0;
	for(i=0,j=0; i<num; i++)
	{
		if( line[i]==ch || line[i]=='\n' )
		{
			line[i]='\0';
			len[j]=i-lasti;
			lasti=i+1;
		}

		if( lastch == '\0' )
		{
			word[j]=(char *)(line+i);
			j++;
			if(j>= maxw)
				return j;
		}

		lastch=line[i];
	}


	len[j]=i-lasti;
	return j;
}


int Split_decode(char *line, char ch,int maxw, char *word[], int len[])
{
	int i,j,num;
	char lastch;
	int lasti;
	
	num=strlen(line);

	lastch='\0';
	lasti=0;
	for(i=0,j=0; i<num; i++)
	{
		if( line[i]==ch || line[i]=='\n' )
		{
			line[i]='\0';
			len[j]=i-lasti;
			lasti=i+1;
		}

		if( lastch == '\0' )
		{
			word[j]=(char *)(line+i);
			j++;
			if(j>= maxw)
				return j;
		}

		lastch=line[i];
	}


	len[j]=i-lasti;
	return j;
}


int ReadLine(const int fd, FileBuff *fb, char *line, int llen)
{
	int i,scan,num,to=0;

	for(i=0; i<llen; i++) line[i]='\0';
	while(1)
	{
		scan=min(fb->num, fb->from+llen-1);
		for(i=fb->from; i<scan; i++) {
			line[to+i-fb->from]=fb->buf[i];
			if(fb->buf[i]=='\n' )	{
				num= ++i-fb->from;
				fb->from=i;
				return num;
			}
		}

		if(fb->num> fb->from+llen-1) {
			line[llen-1]='\n';
			fb->from= (fb->from+llen-1) ;
			return (llen);
		} else {
			to += (i-fb->from);
			fb->from = 0;
			/*bzero(fb->buf,FBUFFSIZE);*/
			memset(fb->buf, '\0', FBUFFSIZE);
			fb->num = read(fd,fb->buf,FBUFFSIZE);

			if(fb->num<0)
			{
				switch(errno) {
				case EINTR:
					printf("EINTR while reading, read will be continue.\n");
					continue;
				default:
					printf("errno:%d %s\n",errno,strerror(errno));
					exit(-1);
				}
			}
			else if(fb->num==0) {
				return 0;
			}
		}
	}
}

int SuperReadLine(const int fd, FileBuff *fb, char *line, int llen, int *flds)
{
	int i,scan,num,to=0;

	*flds=0;
	for(i=0; i<llen; i++) line[i]='\0';
	while(1)
	{
		scan=min(fb->num, fb->from+llen-1);
		for(i=fb->from; i<scan; i++) {
			line[to+i-fb->from]=fb->buf[i];

			if(fb->buf[i]==',')
			{
				(*flds)++;	
			} else if(fb->buf[i]=='\n' ) {
				num= ++i-fb->from;
				fb->from=i;
				return num;
			}
		}

		if(fb->num> fb->from+llen-1) {
			line[llen-1]='\n';
			fb->from= (fb->from+llen-1) ;
			return (llen);
		} else {
			to += (i-fb->from);
			fb->from = 0;
			/*bzero(fb->buf,FBUFFSIZE);*/
			memset(&fb->buf, '\0', FBUFFSIZE);
			fb->num = read(fd,fb->buf,FBUFFSIZE);

			if(fb->num<0)
			{
				switch(errno) {
				case EINTR:
					printf("EINTR while reading, read will be continue.\n");
					continue;
				default:
					printf("errno:%d %s\n",errno,strerror(errno));
					exit(-1);
				}
			}
			else if(fb->num==0) {
				return 0;
			}
		}
	}
}

int WriteLine(const int fd, FileBuff *fb, const char *src, const int length)
{
	size_t	left,from,part;

	left=length;
	from=0;

	while( left>0 ) 
	{
		if(left+fb->num <= FBUFFSIZE) 
		{
			/*bcopy(src+from, fb->buf+fb->num, left);*/
			memcpy(fb->buf+fb->num, src+from, left);
			fb->num += left;
			left = 0;
		}
		else 
		{
			part=FBUFFSIZE-fb->num;
		
			/*bcopy(src+from, fb->buf+fb->num, part);*/
			memcpy(fb->buf+fb->num, src+from, part);
			left -= part;
			from += part;
			WriteN(fd, fb->buf, FBUFFSIZE);
			/*bzero(fb->buf, FBUFFSIZE);*/
			memset(fb->buf, '\0', FBUFFSIZE);
			fb->num=0;
		}
	}
	
	// 将缓存中未满的数据写到文件，以保证一条完整的记录如果需要向文件写入，是在本函数调用一次的过程中完成
	if(fb->num != 0)
	{
		WriteN(fd, fb->buf, fb->num);
		/*bzero(fb->buf, FBUFFSIZE);*/
		memset(fb->buf, '\0', FBUFFSIZE);
		fb->num=0;	
	}
	
	return 0;
}

int ReadN(const int fd, FileBuff *fb, char *block, int size)
{
        size_t  left;
        int     i,to,has;

	to=0;
	left=size;
	while(1)
	{
		has = fb->num - fb->from;
		if( has >= left)
		{
			/*bcopy(fb->buf+fb->from, block+to, left);*/
			memcpy(block+to, fb->buf+fb->from, left);
			fb->from += left;
			return size;
		} else if(has == 0 )
		{
			//bzero(fb->buf,FBUFFSIZE);
			memset(fb->buf, '\0', FBUFFSIZE);
			fb->num = read(fd, fb->buf, FBUFFSIZE);
			if(fb->num < 0) {
				switch(errno) {
				case EINTR:
					continue;
				default:
					printf("errno:%d %s\n",errno,strerror(errno));
					exit(-1);
				}
			}
			else if(fb->num==0) {
				return 0;
			}
		} else
		{
			//bcopy(fb->buf+fb->from, block+to, has);
			memcpy(block+to, fb->buf+fb->from, has);
			to += has;
			left -= has;
			fb->from = 0;
		}
	}
}

int WriteN(const int fd, const char *vptr, const int n)
{
	size_t	left;
	ssize_t	written;
	const char *ptr;

	ptr=vptr;
	left=n;

	while(left>0) {
		written=write(fd,ptr,left);
		if(written<0) {
			switch(errno) {
			case EINTR:
				written=0;
				break;
			default:
				printf("write failure  errno:%d %s\n",errno,strerror(errno));
				return(-1);
			}
		}
		left -= written;
		ptr += written;
	}
	return n;
}

int WriteN_wld(const int fd, const char *vptr, const int n)
{
	size_t	left;
	ssize_t	written;
	const char *ptr;

	ptr=vptr;
	left=n;
	printf("1111 n=[%d] left=[%d] vptr=[%s]\n", n, left, vptr);
	while(left>0) {
		written=write(fd,ptr,left);
		printf("2222 written=[%d]\n", written);
		if(written<0) {
			switch(errno) {
			case EINTR:
				written=0;
				break;
			default:
				printf("write failure  errno:%d %s\n",errno,strerror(errno));
				return(-1);
			}
		}
		left -= written;
		ptr += written;
	}
	
	return n;
}

void Char2BCD(char *src, char *dest, int cnum)
{
	int i;
	if(cnum%2 ) {
		for( i=cnum/2; i>0; i--) {
			dest[i] = 0x0F & src[i*2-1];
			dest[i] |= src[i*2]<<4;
		}
		dest[0] = src[0]<<4;
	}
	else {
		for( i=cnum/2-1; i>=0; i--) {
			dest[i] = 0x0F & src[i*2];
			dest[i] |= src[i*2+1]<<4;
		}
	}
}

void BCD2Char(char *src, char *dest, int cnum)
{
	int i;

	if(cnum%2) {
		for(i=cnum/2; i>0; i--) {
			dest[i*2] = 0x0F & src[i]>>4;
			dest[i*2-1] = 0x0F & src[i];
		}
		dest[0] = 0x0F & src[0]>>4;
	}
	else {
		for(i=cnum/2; i>=0; i--) {
			dest[i*2+1] = 0x0F & src[i]>>4;
			dest[i*2] = 0x0F & src[i];
		}
	}

	for(i=0; i<cnum; i++) dest[i]+=48;
	dest[cnum]='\0';
}

int isSame(char *src, char *dest, int len)
{
	int i;
	for(i=0; i<len; i++)
		if(src[i] != dest[i]) return 0;
	return 1;
}

void *Malloc(unsigned capacity)
{
	void *p;
	p = (void *)malloc(capacity);
	if( p==NULL ) {
		printf("Can't Malloc:%s\n",strerror(errno));
		exit(-1);
	}
	/*else bzero(p, capacity);*/
	else	memset(p, '\0', capacity);
	return p;
}

int Atoi(char *src)
{
	int ret=atoi(src);
	if( ret <= 0 ) {
		printf("src=%s\n",src);
		perror("smLocalContext.conf configure error!");
		exit(-1);
	}
	
	return ret;
}

int ReadConfig(char *filename, Config *cfg)
{
	int i,j,num=1,fd;
	char lastch,*word[5],line[256];
	FileBuff fbuf;

	fbuf.num=0;
	fbuf.from=0;

	/*bzero(cfg, sizeof(Config));*/
	memset(cfg, '\0', sizeof(Config));
	fd=open(filename, O_RDONLY);

	if(fd>0) {
		while( num>0 ) {
			num = ReadLine(fd, &fbuf, line, 256);
			if(num==0) break;
			if(num<5 || line[0]=='#') continue;

			lastch='\0';
			for(i=0,j=0; i<num; i++) {
				if( line[i]!='\t' && line[j]!=0x20 ) {
					if( lastch == '\0' ) {
						word[j]=line+i;
						j++;
						if(j>=3) break; 
					}
				}
				else line[i]='\0';
				lastch=line[i];
			}

			if( !strcasecmp(word[0],"receive_port"))
			{
				strcpy(cfg->receive_port, word[1]);
			}
			else if( !strcasecmp(word[0],"direct_receive"))
			{				
				cfg->direct_receive = Atoi(word[1]);
			}				
			else if( !strcasecmp(word[0],"analyze_thread_num"))
			{
				cfg->analyze_thread_num = Atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"output_file_num"))
			{
				cfg->load_file_num = Atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"monitor_host"))
			{
				strcpy(cfg->monitor_host, word[1]);
			}
			else if( !strcasecmp(word[0],"monitor_port"))
			{
				strcpy(cfg->monitor_port, word[1]);
			}
			else if( !strcasecmp(word[0],"monitor_interval"))
			{
				cfg->monitor_interval=Atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"output_interval"))
			{
				cfg->load_interval=Atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"hash_tune"))
			{
				cfg->hash_tune=atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"context_capacity"))
			{
				cfg->context_capacity=atoi(word[1]);
			}			
			else if( !strcasecmp(word[0],"db_name"))
			{
				strncpy(cfg->db_name, word[1], 15);
			}
			else if( !strcasecmp(word[0],"db_user"))
			{
				strncpy(cfg->db_user, word[1], 15);
			}
			else if( !strcasecmp(word[0],"db_passwd"))
			{
				strncpy(cfg->db_passwd,word[1],15);
			}
			else if( !strcasecmp(word[0],"table_name"))
			{
				strncpy(cfg->table_name, word[1], 50);
			}
			else if( !strcasecmp(word[0],"select_cond"))
			{
				strncpy(cfg->select_cond, word[1], 100);
			}
			else if( !strcasecmp(word[0],"autosave_slice"))
			{
				cfg->autosave_slice=atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"slice_num"))
			{
				cfg->slice_num=atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"init_context_period"))
			{
				cfg->init_context_period= atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"init_context_day"))
			{
				cfg->init_context_day = Atoi(word[1]);
			}			
			else if( !strcasecmp(word[0],"init_context_hour"))
			{
				cfg->init_context_hour= Atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"init_context_min"))
			{
				cfg->init_context_min = Atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"backup_context_interval"))
			{
				cfg->backup_context_interval = Atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"physical_area_table_name"))
			{
				strncpy(cfg->physical_area_table_name, word[1], 50);
			}
			else if( !strcasecmp(word[0],"physical_area_table_cel"))
			{
				strncpy(cfg->physical_area_table_cel, word[1], 20);
			}
			else if( !strcasecmp(word[0],"resident_time_raft"))
			{
				cfg->resident_time_raft = Atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"resident_time_interval"))
			{
				cfg->resident_time_interval = Atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"output_file_prefix"))
			{
				strncpy(cfg->load_file_prefix, word[1], 200);
			}
			else if( !strcasecmp(word[0],"output_file_suffix"))
			{
				strncpy(cfg->output_file_suffix, word[1], 50);
				
				//输出后缀为空，则直接清空
				if(strncmp(cfg->output_file_suffix, "#", 1)  == 0)
				{	
					memset(cfg->output_file_suffix, '\0', sizeof(cfg->output_file_suffix));
				}		
			}			
			else if( !strcasecmp(word[0],"nonparticipant_file_path"))
			{
				strncpy(cfg->nonparticipant_file_path, word[1], 200);
			}	
			else if( !strcasecmp(word[0],"input_file_path"))
			{
				strncpy(cfg->input_file_path, word[1], 200);
			}
			else if( !strcasecmp(word[0],"input_file_backup_path"))
			{
				strncpy(cfg->input_file_backup_path, word[1], 200);
			}
			else if( !strcasecmp(word[0],"sleep_interval"))
			{
				cfg->sleep_interval = Atoi(word[1]);
			}											
			else if( !strcasecmp(word[0],"event_type_filter"))
			{
				cfg->event_type_filter = atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"msisdn_info_table_name"))
			{
				strncpy(cfg->msisdn_info_table_name, word[1], 50);
			}
			else if( !strcasecmp(word[0],"pstn_area_info_table_name"))
			{
				strncpy(cfg->pstn_area_info_table_name, word[1], 50);
			}
			else if( !strcasecmp(word[0],"numbers_prefix_info_table_name"))
			{
				strncpy(cfg->numbers_prefix_info_table_name, word[1], 50);
			}
			else if( !strcasecmp(word[0],"mobile_prefix_table_name"))
			{
				strncpy(cfg->mobile_prefix_table_name, word[1], 50);
			}			
			else if( !strcasecmp(word[0],"imsi_msisdn_flag"))
			{
				cfg->imsi_msisdn_flag = atoi(word[1]);
			}
			else if( !strcasecmp(word[0],"agg_cell_flag"))
			{
				cfg->agg_cell_flag = atoi(word[1]);
			}else if( !strcasecmp(word[0],"signal_sort_flag")){
			   cfg->signal_sort_flag = atoi(word[1]);	
			}
			else if( !strcasecmp(word[0],"signal_sort_capacity")){
			   cfg->signal_sort_capacity = atoi(word[1]);	
			}
			else if( !strcasecmp(word[0],"signal_sort_interval")){
			   cfg->signal_sort_interval = atoi(word[1]);	
			}
			else if( !strcasecmp(word[0],"log_file_path")){
				strncpy(cfg->log_file_path, word[1], 200);
			}
			else if( !strcasecmp(word[0],"host_code")){
				strncpy(cfg->host_code, word[1], 20);
			}
			else if( !strcasecmp(word[0],"entity_type_code")){
				strncpy(cfg->entity_type_code, word[1], 20);
			}
			else if( !strcasecmp(word[0],"entity_sub_code")){
				strncpy(cfg->entity_sub_code, word[1], 20);
			}
			else if( !strcasecmp(word[0],"log_interval"))
			{
				cfg->log_interval = Atoi(word[1]);
			}	
			else if( !strcasecmp(word[0],"err_file_path")){
				strncpy(cfg->err_file_path, word[1], 200);
			}
			else if( !strcasecmp(word[0],"proc_file_path")){
				strncpy(cfg->proc_file_path, word[1], 200);
			}		
			else if( !strcasecmp(word[0],"local_prov_code")){
				strncpy(cfg->local_prov_code, word[1], MAX_CITY_CODE_LEN);
			}
			else if( !strcasecmp(word[0],"other_prov_flag"))
			{
				//printf("other_prov_flag:%s",word[1]);
				cfg->other_prov_flag = atoi(word[1]);
			}	
			else if( !strcasecmp(word[0],"imsi_msisdn_map_file")){
				strncpy(cfg->filename, word[1], 100);
			}									
		}
		
		close(fd);
		
		return 0;
	}
	else {
		perror("Can't open smLocalContext.conf");
		return -1;
	}
}

void PrintCfg(Config *cfg)
{
	printf("\n");
	printf("显示配置文件smLocalContext.conf中信息开始...\n");
	//printf("receive_port:%s\n",cfg->receive_port);
	//printf("direct_receive:%d\n",cfg->direct_receive);
	printf("analyze_thread_num:%d\n",cfg->analyze_thread_num);

	//printf("monitor_host:%s\n",cfg->monitor_host);
	//printf("monitor_port:%s\n",cfg->monitor_port);

	//printf("monitor_interval:%d seconds\n",cfg->monitor_interval);
	printf("hash_tune:%d\n",cfg->hash_tune);
	printf("context_capacity:%d\n",cfg->context_capacity);
	
	printf("input_file_path:%s\n",cfg->input_file_path);
	//printf("input_file_backup_path:%s\n",cfg->input_file_backup_path);	
	printf("sleep_interval:%d seconds\n",cfg->sleep_interval);

	printf("output_file_num:%d\n",cfg->load_file_num);
	printf("output_file_prefix:%s\n",cfg->load_file_prefix);
	printf("output_file_suffix:%s\n",cfg->output_file_suffix);			
	printf("output_interval:%d seconds\n",cfg->load_interval);

	printf("imsi_msisdn_map_file:%s\n",cfg->filename);
				
	//printf("db_name:%s\n",cfg->db_name);
	//printf("db_user:%s\n",cfg->db_user);
	//printf("db_passwd:%s\n",cfg->db_passwd);
	//printf("table:%s\n",cfg->table_name);
	//printf("select_cond:%s\n",cfg->select_cond);
	//printf("autosave_slice:%d seconds\n",cfg->autosave_slice);
	//printf("slice_num:%d\n",cfg->slice_num);
	
	printf("init_context_period:%d\n",cfg->init_context_period);
	printf("init_context_day:%d\n",cfg->init_context_day);	
	printf("init_context_hour:%d\n",cfg->init_context_hour);
	printf("init_context_min:%d\n",cfg->init_context_min);
	//printf("backup_context_interval:%d seconds\n",cfg->backup_context_interval);

	printf("other_prov_flag:%d\n",cfg->other_prov_flag);
	printf("local_prov_code:%s\n",cfg->local_prov_code);
			
	//printf("resident_time_raft:%d mins\n",cfg->resident_time_raft);
	//printf("resident_time_interval:%d mins\n",cfg->resident_time_interval);
				
	printf("显示配置文件smLocalContext.conf中信息结束\n");
	printf("\n");
}

time_t ToTime_t(char *src)
{
	struct tm t;
	time_t totime;

	
	strptime( src, "%Y-%m-%d %H:%M:%S", &t);
	totime = mktime( &t );
	return totime;
}
char *Now(char *now)
{
	struct tm *t;
	struct timeval tval;
	gettimeofday(&tval, (void *)NULL);
	t=localtime(&tval.tv_sec);
	sprintf(now,"%4d-%02d-%02d %02d:%02d:%02d",
		t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour,t->tm_min,t->tm_sec);
	return now;
}
static void ShowTimes(void)
{
	struct tms times_info;
	double ticks;

	if((ticks=(double)sysconf(_SC_CLK_TCK))<0)
		perror("Can't determine clock ticks per second");
	else if(times(&times_info)<0)
		perror("Can't get times information");
	else {
		fprintf(stderr,"User time:%8.3f seconds\n",times_info.tms_utime/ticks);
		fprintf(stderr,"System time:%8.3f seconds\n",times_info.tms_stime/ticks);
		fprintf(stderr,"Children's user time:%8.3f seconds\n",times_info.tms_cutime/ticks);
		fprintf(stderr,"Children's system time:%8.3f seconds\n",times_info.tms_cstime/ticks);
	}
}

void ReadDir(int begin)
{
	char dirname[20];
	DIR *dirp;
	struct dirent *direntp;

	
	strcpy(dirname, ".");
	if((dirp = opendir(dirname)) == NULL ) {
		perror("Can't opendir!");
		exit(1);
	}
	while((direntp = readdir(dirp)) != NULL )
		printf("%s\n",direntp->d_name);

	closedir(dirp);
}

char *CurDir(char *dirname)
{
	 char *cwd;
	 if ((cwd = getcwd(NULL, 64)) == NULL) {
		perror("getcwd failure");
		return cwd;
	 }
	 strcpy(dirname,cwd);
	 return (dirname);
}

int Open(char *path, int oflag)
{
	int fd;

	fd=open(path, oflag, 0644);
	if(fd<=0) {
		printf("Can not open file %s\n",path);
		exit(1);
	}
	return (fd);
}

int PthreadCreate(pthread_t *tid, const pthread_attr_t *attr, void *(start_routine (void *)),void *arg)
{
	int ret;
	ret=pthread_create(tid,attr,start_routine,arg);
	if(ret!=0) {
		printf("Can't create thread!\n");
		exit(1);
	}
	return 0;
}

// 取得系统当前时间
// str_sys_time 返回"1970-01-01 08:00:00"格式字符串
// 函数返回值为秒数
time_t get_system_time(char *str_curr_system_time)
{
	int i;
	time_t curr_system_time;

	struct tm *tp;

	// 取得系统当前时间
	memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
	time(&curr_system_time);
	tp = localtime(&curr_system_time);
	sprintf(str_curr_system_time, "%4d-%02d-%02d %02d:%02d:%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_curr_system_time=[%s]\n", str_curr_system_time);

	return curr_system_time;
}


// 取得系统当前时间
// str_sys_time 返回"19710203040506"格式字符串
// 函数返回值为秒数
time_t get_system_time_2(char *str_curr_system_time)
{
	int i;
	time_t curr_system_time;

	struct tm *tp;

	// 取得系统当前时间
	memset(str_curr_system_time, '\0', sizeof(str_curr_system_time));
	time(&curr_system_time);
	tp = localtime(&curr_system_time);
	sprintf(str_curr_system_time, "%4d%02d%02d%02d%02d%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_curr_system_time=[%s]\n", str_curr_system_time);

	return curr_system_time;
}


// 根据输入时间，转换为YYYYMMDDHHMMSS格式
// str_time 返回"20100315100000"格式字符串
// 函数返回值为tm
tm * get_str_time(char *str_time,time_t t)
{
	struct tm *tp;

	// 取得tm
	memset(str_time, '\0', sizeof(str_time));
	tp = localtime(&t);

	sprintf(str_time, "%4d%02d%02d%02d%02d%02d",
	tp->tm_year+1900,tp->tm_mon+1,tp->tm_mday,tp->tm_hour,tp->tm_min,tp->tm_sec);
	//printf("str_time=[%s]\n", str_time);

	return tp;
}

// 根据输入时间，对分钟和秒钟部分清零
// 获取小时级的时间戳
// str_time 返回"20100315100000"格式字符串
// 函数返回值为time_t
time_t get_hour_time(time_t t)
{
	struct tm *tp;
	time_t t_hour;

	//保留小时，分钟和秒清零
	tp = localtime(&t);
	tp->tm_min=0;
	tp->tm_sec=0;
  t_hour = mktime(tp);
  
	return t_hour;
}

void LTrim(char* str, char ch)
{
	int len, i;
	char* tmp;

	len = strlen(str);
	tmp = str;

	for(i = 0; i < len; i++)
	{
		if(str[i] != ch)
		{
			memcpy(str, tmp + i, len - i);
			str[len - i] = 0;
			return;
		}
	}
}


void RTrim(char* str, char ch)
{
	int len, i;

	len = strlen(str);

	for(i = len - 1; i >= 0; i--)
	{
		if(str[i] != ch)
		{
			str[i + 1] = 0;
			return;
		}
	}

	str[0] = 0;
}


int GetStr(char*    origin, char*    out, int num, char    ch)
{
    int i;
    char*   str1;
    char*   str2;
    str1=origin;
 
    for(i=0;i<num;i++)
    {
        str1=strchr(str1,ch);
        str1=str1+1;
    }
    str2=strchr(str1,ch);
    memcpy(out,str1,str2-str1);
    
    return (str2-str1);
}



/**
*  程序启动时写心跳文件
**/
int write_heart_file(char *filename)
{
	int ret = 1 ;
  char spid[20];
	FILE	*fp;
  char file_path[250];
  
  memset(file_path,'\0',sizeof(file_path));
  strcpy(file_path,filename);
  if((fp=fopen(file_path,"w"))==NULL){
      printf("Cannot write file!");
      ret = 0 ;
  }
  sprintf(spid,"%d",getpid());
  if(fputs(spid,fp) == NULL){
      printf("Cannot fputs data to file!");
      ret = 0 ;  	  
  }
  fclose(fp);
  
  return ret;
}

/**
*  错误告警日志文件
**/
int write_error_file(char *filepath,char *modulename,char *errcode,int level,char *errinfo)
{
  int ret = 1 ;
	FILE	*fp;
  char filename[250];
  char line[500];
  char spid[20],slevel[3];  
  time_t begin_time;
	char str_begin_time[20];   
         
  sprintf(spid,"%d",getpid());  
  sprintf(slevel,"%d",level);                        
	memset(str_begin_time, '\0', sizeof(str_begin_time));
	begin_time = get_system_time_2(str_begin_time);
	  
  memset(filename,'\0',sizeof(filename));
  sprintf(filename,"%s%s_%d_%s.err",filepath,modulename,getpid(),str_begin_time);
  if((fp=fopen(filename,"a+"))==NULL){
      printf("Cannot write file!");
      ret = 0 ;
  }
  
  memset(line,'\0',sizeof(line));
  sprintf(line,"%s	%s	%s	%d	%s	%s	%s	%d	%s\n",chk.host_code,chk.entity_type_code,chk.entity_sub_code,getpid(),modulename,str_begin_time,errcode,level,errinfo);      
  if(fputs(line,fp) == NULL){
      printf("Cannot fputs data to file!");
      ret = 0 ;  	  
  }
  fclose(fp);
  
  return ret;
}

int write_log_file(char *filepath,char *modulename,char *msgcode,char *file_name,char *end_time,char *msgvalue){
	  int ret = 1 ;
	FILE	*ftp_tmp;
  char filename[200],rfilename[200];
  char line[1000];
	  
  memset(filename,'\0',sizeof(filename));
  sprintf(filename,"%s%s.tmp",filepath,modulename); 
  if((ftp_tmp=fopen(filename,"a+"))==NULL){
      printf("Cannot write file!");
      ret = 0 ;
  }
  
  memset(line,'\0',sizeof(line));
  sprintf(line,"%s	%s	%s	%d	%s	%s	%s	%s								 		%s	\n",chk.host_code,chk.entity_type_code,chk.entity_sub_code,getpid(),modulename,end_time,msgcode,file_name,msgvalue);    
  if(fputs(line,ftp_tmp) == NULL){
      printf("Cannot fputs data to file!");
      ret = 0 ;  	  
  }
  fclose(ftp_tmp);
  return ret;
}
