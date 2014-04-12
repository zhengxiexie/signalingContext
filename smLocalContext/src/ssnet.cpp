#include "sspublic.h"
#include "ssnet.h"
#include "sscontext.h"
#include "ssanalyze.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

unsigned int	ss_num=0;	
int exitflag=0;
int file_read_exitflag=0;	
Analyze  ana;	
time_t last_time = 0;

LineBuff lb={
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_COND_INITIALIZER,
	PTHREAD_COND_INITIALIZER,
	LBSIZE,0,0,0
};


Check chk={
        PTHREAD_MUTEX_INITIALIZER,
        PTHREAD_COND_INITIALIZER,
        0,0,0,0,0,0
};

void *produce_fr_tcp(void *arg)
{
	int	fd, connfd;
	char	hostname[64],servname[20];
	struct	sockaddr_in cltaddr;
	struct	addrinfo hints,*res;
	socklen_t socklen, optlen;
	int optval;

	Config *cfg;

	int  num;
	char line[MAXLINE];
	FileBuff fb;

	fb.num=0;
	fb.from=0;


	cfg=(Config *)Malloc(sizeof(Config));
	ReadConfig("../etc/ssanalyze.conf", cfg);

	gethostname(hostname, 64);

	//bzero(&hints, sizeof(hints));
	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	Getaddrinfo(hostname, cfg->receive_port, &hints, &res);

	fd = Socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	Bind(fd, res->ai_addr, res->ai_addrlen);

	listen(fd, 5);
	printf("\nListening data at %s:%s\n",res->ai_canonname,cfg->receive_port);

	optlen=sizeof(optval);
	optval=128*1024;
	Setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&optval, optlen);

	free(cfg);
	freeaddrinfo(res);

	socklen = sizeof(cltaddr);
	while(1)
	{
		connfd = Accept(fd, (struct sockaddr *)&cltaddr, &socklen);

		Getnameinfo((struct sockaddr *)&cltaddr, socklen,
				hostname, 64, servname, 20, NI_NUMERICHOST);
		printf("Sender come from %s:%s\n", hostname, servname);

		while(1)
		{
			num = ReadLine(connfd, &fb, line, MAXLINE);
			if(num<= 0) {
				printf("Connect close\n");
				break;
			}
			
			if( chk.direct_receive && Discard(line, 11))
			{
				printf("column number error: %s\n", line);
				continue;
			}

			pthread_mutex_lock(&lb.mutex);
			while ( lb.empty < MAXLINE)
				pthread_cond_wait(&lb.less, &lb.mutex);

			num=PutLine(line, &lb);

			pthread_cond_signal(&lb.more);
			pthread_mutex_unlock(&lb.mutex);

			//ss_num++;

			if(exitflag>0) 
			{
				// ��û�вɼ�������ʱ����������Ĵ����̣߳�consume���ȴ�����Ҫ�����źţ�ʹ�������������
				// �������ſ����ж��Ƿ���Ҫ�˳�
				pthread_cond_signal(&lb.more);
			
				file_read_exitflag = 1;

				freeaddrinfo(res);
				printf("last msg is:%s\n",line);
				pthread_exit(0);
			}
		}
	}
}

// ����sscontest.cpp��
/*
void *load_timer(void *arg)
{
	int i, load_interval;
	Config *cfg;

	cfg=(Config *)Malloc(sizeof(Config));
	ReadConfig("../etc/ssanalyze.conf", cfg);
	load_interval = cfg->load_interval;
	free(cfg);

	while(1) {
		sleep(load_interval);

		
		//for(i=0; i<7; i++)
		for(i=0; i<LOAD_FILE_NUM; i++)
		{
			ana.timeout[i]=1;
		}
		
		if(exitflag>0) 	pthread_exit(0);
	}
}
*/


void *produce_fr_udp(void *arg)
{
	int sockfd,n=0;
	unsigned long clilen;
	struct sockaddr_in cltaddr;
	unsigned long addrlen;
	struct	addrinfo hints,*res;
	char  msg[MAXLINE];			
	char  hostname[20];
	int optval;
	socklen_t len;
	Config *cfg;

	cfg = (Config *)Malloc(sizeof(Config));
	ReadConfig("../etc/ssanalyze.conf", cfg);

	gethostname(hostname, 64);

	//bzero(&hints, sizeof(hints));
	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	Getaddrinfo(hostname, cfg->receive_port, &hints, &res);

	sockfd = Socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	Bind(sockfd, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	optval= 65536;
	len=sizeof(optval);
	Setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (void *)&optval, len);

	clilen = sizeof(cltaddr);
	free(cfg);

	ss_num=0;
	while(1) {
		int num;

		//bzero(msg, MAXLINE);
		memset(msg, '\0', MAXLINE);
/*		n = recvfrom(sockfd,msg,MAXLINE,0,(struct sockaddr *)&cltaddr,&clilen);20090326*/
		if(n<0) {
			printf("Can't receive data\n");
			continue;
		}

		pthread_mutex_lock(&lb.mutex);
		while ( lb.empty < MAXLINE)
			pthread_cond_wait(&lb.less, &lb.mutex);

		num=PutLine(msg, &lb);

		pthread_cond_signal(&lb.more);
		pthread_mutex_unlock(&lb.mutex);

		//ss_num++;

		if(exitflag>0)
		{
			// ��û�вɼ�������ʱ����������Ĵ����̣߳�consume���ȴ�����Ҫ�����źţ�ʹ�������������
			// �������ſ����ж��Ƿ���Ҫ�˳�
			pthread_cond_signal(&lb.more);
				
			file_read_exitflag = 1;

			freeaddrinfo(res);
			printf("last msg is:%s\n",msg);
			pthread_exit(0);
		}
	}
}

void *produce_fr_ftp(void *arg)
{
	int	fd;
	int  num=1,ret,counts=0;
	time_t event_time,deal_time,begin_time,end_time,cur_time;                     
	char str_begin_time[20],str_cur_time[20],str_end_time[20];  
	char line[MAXLINE];
	char line_tmp[MAXLINE];
	char imsi[16];
	char buff[300];
	int len[50];
	char *word[50];
	char str_event_time[30],errinfo[200];
	char log_file_path[250];
	int signal_sort_capacity = 0;	
  int out_time = 0;
  int match_flag = 0;  
	struct stat file_buf;	
	FileBuff fb;
	fb.num=0;
	fb.from=0;

	DIR				*dp;
	struct dirent *entry;
	struct stat	buf;
	char		*ptr;
	#define MAXLINES 100
	char *fileptr[MAXLINES];
	struct tm *tp;
  SignalContent *end ;
	char input_file_path[200];
	char input_file_backup_path[200];
	char input_file_name[200];
	int sleep_interval=120; //����ȡ�ļ�����,��λ����  Ĭ��Ϊ120��
	// �ж��Ƿ���ֹͣ��־�ļ�
	int fd_exit;

	int init_flag = 1;  //���������������ʼ��
		
	char str_exit_file_name[200];
	memset(str_exit_file_name, '\0', sizeof(str_exit_file_name));
	strcpy(str_exit_file_name, "../../flag/smLocalContext.exitflag");
		
	//vector<string> 	m_input_file_name;
	//vector<string>::iterator 	m_pos_m_input_file_name;

	set<string> 				m_input_file_name;
	set<string>::iterator 		m_pos_m_input_file_name;
	char msgvalue[20];
	// ȡ��sleep����
	//sleep_interval = get_sleep_interval();
	sleep_interval = chk.sleep_interval;
	//printf("sleep_interval=[%d]\n", sleep_interval);

	// ȡ�������ļ�·��
	memset(input_file_path, '\0', sizeof(input_file_path));
	strcpy(input_file_path, chk.input_file_path);
	//get_input_file_path(input_file_path);
	printf("input file path=[%s]\n", input_file_path);

	// ȡ�������ļ��ı���·��
	memset(input_file_backup_path, '\0', sizeof(input_file_backup_path));
	strcpy(input_file_backup_path, chk.input_file_backup_path);
	//get_input_file_backup_path(input_file_backup_path);
	//printf("input_file_backup_path=[%s]\n", input_file_backup_path);

  signal_sort_capacity = chk.signal_sort_capacity *10000;
  SignaltimeIndex * timeIndex = NULL;  
	if( chk.signal_sort_flag == 1 ) {
		  //����ʱ������
		  timeIndex = (SignaltimeIndex *)Malloc(sizeof(SignaltimeIndex)*(chk.signal_sort_interval + 1 ));
		  for(int i = 0 ; i < (chk.signal_sort_interval + 1) ; i++){
		  	 timeIndex[i].signal_time = -1;
		  	 timeIndex[i].index = (SignalIndex *)Malloc(sizeof(SignalIndex)*signal_sort_capacity);
	       for(int j=0; j < signal_sort_capacity ; j++){
	            timeIndex[i].index[j].head = NULL;
	       }			  	 
	       int size=sizeof(SignalIndex)*signal_sort_capacity;
	       printf("SignalIndex[%d] size:%.2f MB\n",i,(double)size/1048576);
		  }
  }
  
  //����ѭ����ȡ�ļ�
	while(1){
		if((dp = opendir(input_file_path)) == NULL){
			   memset(errinfo,'\0',sizeof(errinfo));
			   sprintf(errinfo,"·��[%s]�򿪴��������Ŀ¼�Ƿ���ڡ�", input_file_path);
			   printf("%s\n",errinfo);		   
			   write_error_file(chk.err_file_path,"saTimeMonitor","31",3,errinfo);
			   sleep(5*60);
			   continue;
		}else {
			    m_input_file_name.clear();
        	while((entry = readdir(dp)) != NULL){
        		memset(input_file_name, '\0', sizeof(input_file_name));
        		strcpy(input_file_name, input_file_path);
        		strcat(input_file_name, "/");
        		strcat(input_file_name, entry->d_name);

        		if((strcmp(input_file_name, ".")== 0) || (strcmp(input_file_name, "..")== 0)){
					      continue;
				    }

				    if (lstat(input_file_name, &buf) < 0){
					     continue;
				    }

				    if (!S_ISREG(buf.st_mode)){
					     continue;
				    }

						//������ʱ�ļ����򲻴���				    
				    if(strstr(input_file_name, ".tmp") != NULL )
						{
						   continue;
						}
										    
				    m_input_file_name.insert(entry->d_name);
		     }
			   closedir(dp);	
				    
			   //��ʼѭ������ÿһ���ļ�
			   for(m_pos_m_input_file_name=m_input_file_name.begin(); m_pos_m_input_file_name!=m_input_file_name.end(); ++m_pos_m_input_file_name){
				    memset(input_file_name, '\0', sizeof(input_file_name));
        	 	strcpy(input_file_name, input_file_path);
        	 	strcat(input_file_name, "/");
        	 	strcat(input_file_name, m_pos_m_input_file_name->c_str());
				   
				    memset(str_begin_time, '\0', sizeof(str_begin_time));
				    begin_time = get_system_time_2(str_begin_time);
				    last_time = begin_time;             
				    printf("��ǰ�����ļ� [%s] begin_time=[%s]\n", input_file_name, str_begin_time);
				    fflush(stdout); 
        	 	 
        	 	//��ȡ�ļ�����������     
           	if( chk.signal_sort_flag == 1 ) {
                char str_deal_time[20];
				        memset(str_deal_time, '\0', sizeof(str_deal_time));
                strncpy(str_deal_time,m_pos_m_input_file_name->c_str()+5,14);                               
                str_deal_time[18] = '0';
                str_deal_time[17] = '0';
                str_deal_time[16] = ':';
                str_deal_time[15] = str_deal_time[11];                                
                str_deal_time[14] = str_deal_time[10];  
                str_deal_time[13] = ':';                  
                str_deal_time[12] = str_deal_time[9];  
                str_deal_time[11] = str_deal_time[8];                  
                str_deal_time[10] = ' ';  
                str_deal_time[9] = str_deal_time[7];  
                str_deal_time[8] = str_deal_time[6];                 
                str_deal_time[7] = '-'; 
                str_deal_time[6] = str_deal_time[5]; 
                str_deal_time[5] = str_deal_time[4]; 
                str_deal_time[4] = '-'; 
                deal_time = ToTime_t(str_deal_time);
                if(deal_time < 0){
                		 memset(errinfo,'\0',sizeof(errinfo));
			               sprintf(errinfo,"�ּ����ļ�[%s]�����������⣬��������飡", input_file_name);
			               printf("%s\n",errinfo);			   
			               write_error_file(chk.err_file_path,"smLocalContext","32",2,errinfo);	
                }                 				    
				      	
				      	//�ҵ���ǰ�ļ������ʱ��,�����ļ���
				      	//��Ϊÿ���ӵ������ļ���һ��ֻ��һ����������Ҫ���ж��������Ƿ����				      	
				      	//printf("str_deal_time=[%s]  deal_time=[%d]\n",str_deal_time,deal_time);
				      	//���ǵ��ļ������˳��������ᵼ���ļ��������ǣ���ֻ������ʱ�Ǳ���������ֱ���޳�
				      	//�����˳�ʱ�����ݷ�д�������ļ��У������������ٴ�ʹ�ã��Ͳ��Ḳ��
				      	if(init_flag == 1) {
				      		  time_t tmp_time;
				      		  tmp_time = deal_time;				      	    
                    for(int i = chk.signal_sort_interval ; i>= 0 ; i-- ){
				      	    	 timeIndex[i].signal_time = tmp_time;
				      	    	 //printf("[%d]=[%d]\n",i,tmp_time);
				      	    	 tmp_time = tmp_time - 60;
				      	    }
				      	    init_flag = 0 ;  //��ʼ��ʱֻ��һ��	
				      	}else{			
				      			match_flag = 0 ; 
                		for( out_time = 0 ; out_time < (chk.signal_sort_interval +1)  ; out_time++) {
                			    if(timeIndex[out_time].signal_time > 0 && (deal_time - timeIndex[out_time].signal_time) == 0){
                			        	match_flag = 1 ;
                			        	break;
                			    }
                		}
 				      			//printf("match_flag=[%d]\n",match_flag);               
                		if(match_flag != 1){
                			for( out_time = 0 ; out_time < (chk.signal_sort_interval + 1)  ; out_time++) {
                			    if(timeIndex[out_time].signal_time == -1 ){
                		             timeIndex[out_time].signal_time  = deal_time ; 
                		             break;              	        	
                			    }
                			}                	  
                		}	
              	}					      	
				    }
				    
				    // �����ļ��е�ÿ������
				    fd=open(input_file_name, O_RDONLY);
				    num = 1;
				    counts = 0;
            //�ж������Ƿ���Ҫ���� 1-Ϊ��Ҫ��0-Ϊ����Ҫ
		        if( chk.signal_sort_flag == 1 ) {	
				        while( num > 0 ){
					        // ȡ���ļ��е�ÿ����¼
					        num = ReadLine(fd, &fb, line, MAXLINE);	// ��num==0ʱ����ʾ�ѵ����ļ�β�����޿ɶ�ȡ������					
					        if( num > 0 ){
		                 //printf("��ǰ������������Ϊ=[%s]\n", line);
		                 memset(line_tmp, '\0', sizeof(line_tmp));
		                 strcpy(line_tmp, line);		        
		                 //ȡIMSI
		                 ret=Split(line, ',', 50, word, len);	
	                   memset(imsi, '\0', sizeof(imsi));
	                   strcpy(imsi, word[field_imsi_num]);
	                   LTrim(imsi, ' ');
	                   RTrim(imsi, ' ');
	                   
										 //�������¼�ʱ���н�ȡ19λ
										 memset(str_event_time, '\0', sizeof(str_event_time));
										 strncpy(str_event_time, word[field_time_stamp_num], 19);
										 //strcpy(word[field_time_stamp_num], str_event_time);	                   
                     //ȡ�����ʱ��
                     event_time = ToTime_t(str_event_time);	                   
		                 
		                 //�ж���������ĸ�ʱ���б�
		                 match_flag = 0 ;
		                 int time_interval = 0;
                     for( out_time = 0 ; out_time < (chk.signal_sort_interval +1)  ; out_time++) {
                     	 //�ļ���ʱ����ǰһ���ӵ�����
                     	 time_interval = event_time - timeIndex[out_time].signal_time  ;
                	     if(timeIndex[out_time].signal_time > 0 && time_interval >= 0 && time_interval < 60){ 
                	        	match_flag = 1 ;
                	        	break;
                	     }
                     }
                     //printf("match_flag===[%d] \n",match_flag);
                     //����ʱ�ӣ������
                     if(match_flag != 1){
                        //printf("discard...imsi=[%s]\n",imsi);                     	
                        continue;	
                     }
                     //printf("out_time=[%d],event_time=[%s],imsi=[%s]\n",out_time,word[field_time_stamp_num],imsi);
		                 //���������ݽ�������		                 
				             ret=sortSignal(timeIndex[out_time].index,imsi,event_time,line_tmp);		               				            					
					        }
					        counts++;
				        }				    
				        cur_time = get_system_time_2(str_cur_time);     
				        printf("�ļ�������� [%s] str_cur_time=[%s]\n", input_file_name, str_cur_time);	

				        //��ǰN���ӵ��������
				        int min_index = 0;
				        time_t tmp_time = -1 ;				               		    				                          
                end = NULL; 
                for( out_time = 0 ; out_time < (chk.signal_sort_interval +1)  ; out_time++) {
                 	   	//printf("out_time=[%d]\n",timeIndex[out_time].signal_time);
                	   if(timeIndex[out_time].signal_time == -1){
                	   	  continue;
                	   	}

                	   	if(tmp_time == -1 ){
                	   		  tmp_time =  timeIndex[out_time].signal_time ;
                	   	}  
                	   
                	   	if(tmp_time > timeIndex[out_time].signal_time){
                	   	     tmp_time = timeIndex[out_time].signal_time;
                	   	     min_index = out_time;
                	   	}
                }
               // printf("aaaa==[%d]\n",min_index);
                //printf("deal_time=[%d],timeIndex[%d].signal_time=[%d]\n",deal_time,out_time,timeIndex[out_time].signal_time);
               
                /*if(timeIndex[out_time].signal_time > 0 && ((deal_time - timeIndex[out_time].signal_time)/60) >= chk.signal_sort_interval){               	       
 				        for(int i=0; i < signal_sort_capacity; i++){   				        	
					       		while(timeIndex[min_index].index[i].head != NULL){	
					      */ 			
                if(timeIndex[min_index].signal_time > 0 && ((deal_time - timeIndex[min_index].signal_time)/60) >= chk.signal_sort_interval){               	       
 				       		 for(int i=0; i < signal_sort_capacity; i++){   				        	
					       			while(timeIndex[min_index].index[i].head != NULL){						       			
					                        
                    		 pthread_mutex_lock(&lb.mutex);
				        	    	 while ( lb.empty < MAXLINE){
				        	         pthread_cond_wait(&lb.less, &lb.mutex);
				        	    	 }           
				        	    	 num=PutLine(timeIndex[min_index].index[i].head->line, &lb);  
				        	    	 //printf("push to buffer:line=[%s]\n",timeIndex[min_index].index[i].head->line);                  
				        	    	 pthread_cond_signal(&lb.more);
				        	    	 pthread_mutex_unlock(&lb.mutex);		
				        	    		      	 					      	 			 	                 
                        end = timeIndex[min_index].index[i].head->next;
                        free(timeIndex[min_index].index[i].head);
                        timeIndex[min_index].index[i].head = end;
                    }                   		     
				        }
				        timeIndex[min_index].signal_time  = -1 ;
               }
                
				        cur_time = get_system_time_2(str_cur_time);  
				        printf("���뻺����� [%s] str_cur_time=[%s]\n", input_file_name, str_cur_time);	 
				      }else{
                while( num > 0 ){
					        // ȡ���ļ��е�ÿ����¼
					        num = ReadLine(fd, &fb, line, MAXLINE);	// ��num==0ʱ����ʾ�ѵ����ļ�β�����޿ɶ�ȡ������					
					        if( num > 0 ){
                        pthread_mutex_lock(&lb.mutex);
				             		while ( lb.empty < MAXLINE){
				             			     pthread_cond_wait(&lb.less, &lb.mutex);
				             		}           
				             		num = PutLine(line, &lb);                     
				             	  pthread_cond_signal(&lb.more);
				             		pthread_mutex_unlock(&lb.mutex);		               				            					
					        }
					        counts++;
				        }				    				      	
				      }
					    close(fd);			      
					      			        	                        				  		      				      
				      //д�ļ�������־    				      
				      char str_file_name[50];
				      memset(str_file_name,'\0',sizeof(str_file_name));
				      strcpy(str_file_name,m_pos_m_input_file_name->c_str());
				      sprintf(msgvalue,"%d",counts);
				      
				      pthread_mutex_lock(&pthread_logfile_mutex);			
					    ret = write_log_file(chk.log_file_path,"smLocalContext","71",str_file_name,str_end_time,msgvalue); 
		          pthread_mutex_unlock(&pthread_logfile_mutex);

				      if(ret <= 0){
                	memset(errinfo,'\0',sizeof(errinfo));
			            sprintf(errinfo,"д�ļ�������־ʧ��:[%s]",input_file_name);
			            printf("%s\n",errinfo);			   
			            write_error_file(chk.err_file_path,"smLocalContext","35",2,errinfo);					      	
				      }
				      
				      cur_time = get_system_time_2(str_cur_time);     
				      printf("д��־��� [%s] str_cur_time=[%s]\n", input_file_name, str_cur_time);	
				        		          
				      //���ݴ�����ɵ��ļ�
				      /*memset(buff, 0, sizeof(buff));
				      strcpy(buff, "mv ");
				      strcat(buff, input_file_name);
				      strcat(buff, " ");
				      strcat(buff, chk.input_file_path);
				      strcat(buff,"/bak/");
				      printf("buff = [%s]\n", buff);
				      system(buff);*/
				      
				      remove(input_file_name);
				      
				      //ɾ��������ɵ��ļ�				
				      /*memset(buff, 0, sizeof(buff));
				      strcpy(buff, "rm -fr ");
				      strcat(buff, input_file_name);
				      printf("buff = [%s]\n", buff);
				      system(buff);	*/

				      cur_time = get_system_time_2(str_cur_time);     
				      printf("���ļ��������[%s] str_end_time=[%s]\n", input_file_name, str_cur_time);
				        				      
				      fd_exit =open(str_exit_file_name, O_RDONLY);
				      if(fd_exit>0) {
					      printf("��⵽ֹͣ�ļ����ڣ������˳���\n");	
					      exitflag=1;
					      close(fd_exit);
					      remove(str_exit_file_name);
					      break;
				      }				
			   }

			  if(exitflag <= 0){
				  fd_exit =open(str_exit_file_name, O_RDONLY);
				  if(fd_exit>0) {
					  printf("��⵽ֹͣ�ļ����ڣ������˳���\n");	
					  exitflag=1;
					  close(fd_exit);
					  remove(str_exit_file_name);
				  }
			  }
		
			 if(exitflag > 0){				
        //������������PUT�������Ļ�����
		    if( chk.signal_sort_flag == 1 ) {
            end = NULL ;
            char filetime[20];
	                 
            for(int j = 0 ; j < (chk.signal_sort_interval + 1); j++){ 
            	if(timeIndex[j].signal_time == -1){
            		 continue;
            	}
            		memset(filetime,'\0',sizeof(filetime));
            		get_str_time(filetime,timeIndex[j].signal_time);
				   			memset(input_file_name, '\0', sizeof(input_file_name));
        	 			strcpy(input_file_name, input_file_path);
        	 			strcat(input_file_name, "/pick_");
        	 			strcat(input_file_name, filetime);
        	 		
        	 			//��ʼ��BUFFER
								fb.num=0;
								fb.from=0;
								memset(fb.buf,'\0',sizeof(fb.buf));
							
        	 			printf("exit write file name=[%s]\n",input_file_name);
              	fd = open(input_file_name, O_WRONLY|O_CREAT, 0644);
            		for(int i=0; i < signal_sort_capacity; i++){   				        	
				    	 		while(timeIndex[j].index[i].head != NULL){	                
                    pthread_mutex_lock(&lb.mutex);
				            while ( lb.empty < MAXLINE){
				            	 pthread_cond_wait(&lb.less, &lb.mutex);
				            }   
				            WriteLine(fd,&fb,timeIndex[j].index[i].head->line,strlen(timeIndex[j].index[i].head->line));  
				           // num=PutLine(timeIndex[j].index[i].head->line, &lb);                    
                     //printf("line=[%s]\n",timeIndex[j].index[i].head->line);
				            pthread_cond_signal(&lb.more);
				            pthread_mutex_unlock(&lb.mutex);				      	 					      	 			 	                 
                    end = timeIndex[j].index[i].head->next;
                    free(timeIndex[j].index[i].head);
                    timeIndex[j].index[i].head = end;
                 	}                    	     
				    		}
				    		//��󽫻���д���ļ������ر��ļ���
	            	if(fb.num>0)  write(fd, fb.buf, fb.num);
	            	close(fd);				    	
				    		free(timeIndex[j].index);
				    	}				    
				    free(timeIndex);
			  }
				
				file_read_exitflag = 1;
				pthread_cond_signal(&lb.more);
				m_input_file_name.clear();
				memset(errinfo,'\0',sizeof(errinfo));
			  sprintf(errinfo,"��ȡ�ļ������������߳��˳�,������飡");		
			  printf("%s\n",errinfo);   
			  write_error_file(chk.err_file_path,"smLocalContext","64",2,errinfo);	
				pthread_exit(0);
			}
		}
		sleep(sleep_interval);
	}
}



/*�Կͻ������������*/
int sortSignal(SignalIndex *signalIndex,char * imsi,time_t event_time, char * line){
	  SignalContent *content = NULL;
	  SignalContent *end = NULL;   	
	  SignalContent *begin = NULL;   
	  int imsino,pos;
    
		imsino = atoi(imsi+6);			
		
		pos = imsino % (chk.signal_sort_capacity *10000);   					 
	
		//����һ���ڵ�
	  content = (SignalContent *)Malloc(sizeof(SignalContent));
	  memset(content, '\0', sizeof(SignalContent));		
	  //��ֵ
	  content->event_time = event_time;
    memcpy(content->line,line,strlen(line));
    content->next = NULL; 
    
    //�����������ݡ��롯����
	  if( signalIndex[pos].head == NULL) {
    	signalIndex[pos].head = content ;			
	  }else{
	  	begin = end = signalIndex[pos].head ;
	  	while(end != NULL){
	  		   if(event_time <= end->event_time){
	  		   	  if(end == signalIndex[pos].head){
	  		   	  	 content->next = end;
	  		   	  	 signalIndex[pos].head = end = content;
	  		   	  }else{
	  		   	  	begin->next = content;
	  		   	  	content->next = end;
	  		   	  }
	  		   	  break;
	  		   }else{
	  		   	  begin = end;
              end = end->next;
           }
      }
      //���ֵ��󣬷����������
      if(end == NULL) {
          begin->next = content;	
      }      	 		 
	  }
	  begin = end = NULL;	  
	  return 0;
}




int Getaddrinfo(char *hostname,char *servname,struct addrinfo *hints,struct addrinfo **res)
{
	int error;

	hints->ai_flags = AI_PASSIVE|AI_CANONNAME;
	error = getaddrinfo(hostname, servname, hints, res);
	if (error != 0) {
		printf("getaddrinfo:%s for host %s service %s\n",
		strerror(error), hostname, servname);
		exit(-1);
	}
	return 0;
}

int Getnameinfo(struct sockaddr *sa, socklen_t salen,char *host,size_t hostlen,char *serv,size_t servlen,int flags)
{
	int error;
	error = getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
	if( error != 0 ) {
		perror("Getnameinfo");
		exit(-1);
	}
	return 0;
}

struct hostent *Gethostbyname(const char *hname )
{
	struct hostent *hent;
	hent = gethostbyname(hname);
	if(hent==NULL) {
		perror("gethostbyname exec failure");
		exit(-1);
	}
	return hent;
}

int Socket(int family, int type, int protocol)
{
	int ret;
	if((ret=socket(family,type,protocol))<0 ) {
		perror("Socket failure");
		exit(ret);
	}
	return ret;
}

int Bind(int fd, const struct sockaddr *sockaddr, int size)
{
	int ret;
	if((ret=bind(fd,sockaddr,size))<0) {
		printf("Bind failure.\nMaybe the other one is running.\n");
		exit(ret);
	}
	return ret;
}

int Accept(int fd, struct sockaddr *sockaddr, socklen_t *addrlen)
{
	int ret;
	if ((ret=accept(fd,sockaddr,addrlen))<0) {
		perror("Accept failure");
		exit(ret);
	}
	return ret;
}

int Connect(int fd, struct sockaddr *sockaddr, socklen_t addrlen)
{
	int ret;
	if((ret=connect(fd,sockaddr,addrlen))<0) {
		perror("Connect failure,maybe server not running");
		return (ret);
	}
	return ret;
}

int Setsockopt(int s, int level, int optname, void  *optval, socklen_t optlen)
{
	int ret;
	if((ret=setsockopt(s, level, optname, optval, optlen))<0) {
		perror("Setsockopt");
		return -1;
	}
	return ret;
}
