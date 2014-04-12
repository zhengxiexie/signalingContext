#include "sspublic.h"
#include "sscontext.h"
#include "ssoracle.h"

#include <iostream>

//set<string> 				m_physical_area;

// 保存国内长途区号信息
int	m_pstn_area_info[1000];

// 保存手机号码的本外地与区号信息
char	**m_msisdn_info;
int	msisdn_num;

// 保存号码的前缀信息
char	**m_numbers_prefix_info;
int	numbers_prefix_info_num;

// 保存手机号码前缀信息 如135、136
int		mobile_prefix_type[MAX_MOBILE_PREFIX_NUM];
int		mobile_prefix_num;
char	**mobile_prefix_area;

static OCIEnv           *envhp;
static OCIError         *errhp;
static OCISvcCtx        *svchp;
static OCIStmt          *stmthp;
static OCIDefine        *dfnp     = (OCIDefine *) 0;
static OCIDefine        *dfnp2    = (OCIDefine *) 0;
static OCIDefine        *dfnp3    = (OCIDefine *) 0;
static OCIBind          *p_bnd    = (OCIBind *) 0;
FILE *TRACE_FD;

int rowcounts(char *tablename)
{
	int rc;
	int row_nums = 0;
  char sqlstring[128];
  char            errbuf[100];
  int             errcode;
   
   /* set sql statement */
   strcpy(sqlstring,"select count(*) as month from ");
   strcat(sqlstring, tablename);
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
	
   printf("in rowcounts,len=%d,sqlstring=%s\n",strlen(sqlstring),sqlstring);
                 
   /* Define the select list items */
   rc =   OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) &row_nums,
           sizeof(int), SQLT_INT, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
           
   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);
   		
  if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
   }

  printf("rowcounts row_nums=%d\n",row_nums);	 

	return row_nums;
}


int count_rows(char *tablename, char *cond)
{
	int rc;
	int row_nums = 0;
  char sqlstring[128];
  char            errbuf[100];
  int             errcode;
   
  //printf("查询参数信息 tablename=%s cond=%s\n",tablename,cond);
  
  /* set sql statement */
  strcpy (sqlstring, "SELECT count(*) from ");
	strcat(sqlstring, tablename);
	if(strlen(cond)>0) {
		strcat(sqlstring, " where ");
		strcat(sqlstring, cond);
	}
	    
   //printf("查询语句 len=%d, sqlstring=%s\n",strlen(sqlstring),sqlstring);
   
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                            
   /* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) &row_nums,
           sizeof(int), SQLT_INT, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
                      
   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);
 
  if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
   }
    
 	printf("rowcounts: tablename:%s cond=%s row_nums:%ld  \n",tablename,cond,row_nums); 

	return row_nums;
}


int clear_table(char *tablename) 
{
	int  rc;
  char sqlstring[128];
  char            errbuf[100];
  int             errcode;
   
  /* set sql statement */
  strcpy (sqlstring, "truncate table ");
	strcat(sqlstring, tablename);

	    
   /* set sql statement */
   printf("in rowcounts,len=%d,sqlstring=%s\n",strlen(sqlstring),sqlstring);
  
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                 
   /* Execute the SQL statment only execute*/
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);

    /*======= . 错误处理 =====*/
    if(rc != OCI_SUCCESS) {
    		printf("in clear_table,OCIStmtExecute failed \n");
    	
    	  /* 用途 : 回滚发送到数据库的事务*/
    		//rc = 	OCITransRollback(svchp,errhp,(ub4)OCI_DEFAULT);
    }
    
   printf("int clear_table,OCIStmtExecute rc=%d\n",rc);

  if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
   }
	 else {	
  	 /*Execute transaction commit*/
  	// rc = OCITransCommit(svchp,errhp,(ub4)0);
   	 printf("int clear_table,OCITransCommit rc=%d\n",rc);
   }	 
	 return rc;
}


int read_conflict(char *tablename, char *cond)
{
	int rc=1;
	char errbuf[100];
  int  errcode;
	int pos;
	int ci,rj;
	int imsino;
	char sqlstring[128];
	char msisdn[16];
	char imsi[16];
	int row_nums=0;
	char array_msisdn[MAX_EXTRACT_ROW][16];
	char array_imsi[MAX_EXTRACT_ROW][16];
	int leave =0;
	int fetch_row_num=0;
	int loop=0;
	ub4 fetch_num=0;
  
	int curr_i=0; 
  
	//获取msisdn表中根据查询条件获取的数据总行数
	row_nums = count_rows(tablename,cond);
	//cout << "in read_conflict,the row count =" << row_nums << endl;  

	printf("查询参数信息 tablename=%s cond=%s\n",tablename,cond);

	memset(sqlstring, '\0', 128);
	strcpy (sqlstring, "SELECT msisdn,imsi FROM  ");
	strcat(sqlstring, tablename);
	if(strlen(cond)>0)
	{
		strcat(sqlstring, " where ");
		strcat(sqlstring, cond);
	}
	
	//printf("in read_conflict,tablename=%s cond=%s\n",tablename,cond);
	printf("查询语句 sqlstring=[%s]\n", sqlstring);
   
	/* Define the select list items */
	rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);               
           
	/* Define the select list items */
	rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) array_msisdn,
           (sword) 16, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);

	/* Define the select list items */
	rc = OCIDefineByPos(stmthp, &dfnp2, errhp, 2, (dvoid *) array_imsi,
           (sword) 16, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
   
	//cout <<"test000" << endl;   
	rc = OCIDefineArrayOfStruct(dfnp, errhp, 16, 0, 0, 0);
	rc = OCIDefineArrayOfStruct(dfnp2, errhp, 16, 0, 0, 0);
   
	//cout << "test0001"<<endl;
   
	/* Execute the SQL statment */
	leave = row_nums - MAX_EXTRACT_ROW;
   
	//每次读取设置的最大行数或剩余行数
	if(leave > 0 )
	{
		fetch_row_num = MAX_EXTRACT_ROW;
	} 
	else 
	{
		fetch_row_num = row_nums;
	}
 	 
	fetch_num = fetch_row_num;
 	 
	//cout << "fetch_row_num=" << fetch_row_num <<endl;
 	  
	rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) fetch_num, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT); 	 	

	if (rc != OCI_SUCCESS) {
		OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
		printf("Error - %.*s\n", 512, errbuf);
		printf("Error in read_conflict\n");
		exit(8);
	}
	else
	{
		//cout << "test0004 fetch_num=" <<fetch_num <<" fetch_row_num=" << fetch_row_num  <<endl;
   		ci=rj=0;
		while (rc != OCI_NO_DATA)
		{             /* Fetch the remaining data */
			//一次读取数组中的一条记录，
  			//cout << "test0005 ci=" <<ci <<" fetch_row_num=" << fetch_row_num  <<endl;
    		for(loop = 0; loop < fetch_row_num; loop++)
    		{				
    			memcpy(msisdn,array_msisdn[loop],  16);
    			memcpy(imsi,array_imsi[loop],  16);
    			
				/*
    			if (ci < 10 || ci > 1799900)
    			{
    				cout << "Test0006 ci=" <<ci <<" fetch_row_num=" <<fetch_row_num  <<" msisdn=" <<msisdn <<" imsi=" <<imsi <<endl;
    			}
				*/
				imsino = atoi(imsi+6);
        	
				pos = imsino % (chk.context_capacity-chk.hash_tune);
				//printf("wld imsi:%s imsino:%d pos=[%d]\n",imsi,imsino, pos);	
				if( Index[pos].offset == -1)
				{
					Index[pos].offset = ci;
				}
				else 
				{
					if( Index[pos].redirect == -1)
					{
						Index[pos].redirect = rj;
					}
					rj++;
					//printf("1111111111111111111111\n");
				}
					
				ci++;

    			if(curr_i%100000 == 0)
				{
					printf("初始化 curr_i=[%d]条\n", curr_i);
				}
						
				curr_i++;
			}

			//数据库中数据均读取完，则返回
			if(leave <= 0 ) 
			{
				//return rj;
				break;
			}
				  
			leave = leave - MAX_EXTRACT_ROW;
					
			//每次读取设置的最大行数或剩余行数
   			if(leave > 0 )
   			{
				fetch_row_num = MAX_EXTRACT_ROW;
   			} 
   			else 
 	 		{
				fetch_row_num = leave + MAX_EXTRACT_ROW;
			}
 	 				
			fetch_num = fetch_row_num;
			//cout << "test0010 ci =" <<ci <<" fetch_row_num=" << fetch_row_num <<" fetch_num=" << fetch_num  <<endl;
      		
			rc = OCIStmtFetch(stmthp, errhp, fetch_num, 0, 0);
		}
	}

	printf("in read_conflict rc=%d 总记录数(ci)=%d, imsi取模重复次数(rj)=%d \n",rc,row_nums,rj);

	return rj;
}


int read_context(char *tablename, char *cond)
{
	int rc=1;
	char errbuf[100];
  int  errcode;
  char sqlstring[128];
	int pos,next;
	int ci,rj,conflict=0;
	int imsino;
	//char bcdimsi[6];
	char bcdimsi[MAX_BCD_IMSI_LEN];
	char msisdn[16];
	char imsi[16];
	int row_nums=0;
	char array_msisdn[MAX_EXTRACT_ROW][16];
	char array_imsi[MAX_EXTRACT_ROW][16];
	int leave =0;
	int fetch_row_num=0;
	int loop=0;
	ub4 fetch_num=0;
  
	int curr_i=0; 
  
	//获取msisdn表中根据查询条件获取的数据总行数
	row_nums = count_rows(tablename,cond);
	//cout << "in read_context,the row count =" << row_nums << endl;  

	printf("查询参数信息 tablename=[%s] cond=[%s]\n",tablename,cond);

	memset(sqlstring, '\0', 128);
	strcpy (sqlstring, "SELECT msisdn,imsi FROM  ");
	strcat(sqlstring, tablename);
	if(strlen(cond)>0) {
		strcat(sqlstring, " where ");
		strcat(sqlstring, cond);
	}
	
	//printf("in read_context,tablename=%s cond=%s\n",tablename,cond);
	printf("查询语句 sqlstring=[%s]\n", sqlstring);
   
	/* Define the select list items */
	rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);               
           
	/* Define the select list items */
	rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) array_msisdn,
           (sword) 16, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);

	/* Define the select list items */
	rc = OCIDefineByPos(stmthp, &dfnp2, errhp, 2, (dvoid *) array_imsi,
           (sword) 16, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
   
	rc = OCIDefineArrayOfStruct(dfnp, errhp, 16, 0, 0, 0);
	rc = OCIDefineArrayOfStruct(dfnp2, errhp, 16, 0, 0, 0);
   
	/* Execute the SQL statment */
	leave = row_nums - MAX_EXTRACT_ROW;
   
	//每次读取设置的最大行数或剩余行数
	if(leave > 0 ){
   	   fetch_row_num = MAX_EXTRACT_ROW;
	} 
	else 
	{
		fetch_row_num = row_nums;
	}
 	    
	fetch_num = fetch_row_num;
 	 
	//cout << "in read_context,fetch_row_num=" << fetch_row_num <<" fetch_num=" << fetch_num  <<endl;
 	  
	rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) fetch_num, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);	 	
           
	//cout << "in read_context,after OCIStmtExecute"  <<endl;
 	 
	if (rc != OCI_SUCCESS) {
		OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
		printf("Error - %.*s\n", 512, errbuf);
		printf("Error in read_context\n");
		exit(8);
	}
	else
	{
   		ci=rj=0;
   		//cout << "test0004 fetch_num=" <<fetch_num <<" fetch_row_num=" << fetch_row_num  <<endl;
    	while (rc != OCI_NO_DATA) {             /* Fetch the remaining data */
  				//一次读取数组中的一条记录，
    			for(loop = 0; loop < fetch_row_num; loop++)
    			{
    				//memcpy(msisdn,array_msisdn[loop],  16);
    				strcpy(msisdn, array_msisdn[loop]);		
    				memcpy(imsi,array_imsi[loop],  16);
    		/*		
    				if (ci < 100 || ci > 1799900)
    				{
    					cout << "Test0006 ci=" <<ci <<" fetch_row_num=" <<fetch_row_num  <<" msisdn=" <<msisdn <<" imsi=" <<imsi <<endl;
    				}
    		*/			
    					if (ci== chk.context_capacity)
    					{
    						break;
						}

    					if(curr_i%100000 == 0)
						{
							printf("加载 curr_i=[%d]条\n", curr_i);
						}
        		
    					//Char2BCD(msisdn, context[ci].msisdn, 11);
    					strcpy(context[ci].msisdn, msisdn);	
    	  		
							imsino = atoi(imsi+6);
							pos = imsino % (chk.context_capacity-chk.hash_tune);
    					
							//Char2BCD(imsi+4,  bcdimsi, 11);
							Char2BCD(imsi,  bcdimsi, 15);
    					
							if( Index[pos].offset == -1) {
								Index[pos].offset = ci;
								//bcopy(bcdimsi, Index[pos].imsi, 6);
								bcopy(bcdimsi, Index[pos].imsi, MAX_BCD_IMSI_LEN);
							}
							else {
								next=Index[pos].redirect;
								if(next == -1)
								{
									Index[pos].redirect = rj;
									//bcopy(bcdimsi, redirect[rj].imsi, 6);
									bcopy(bcdimsi, redirect[rj].imsi, MAX_BCD_IMSI_LEN);
									redirect[rj].offset = ci;
								}
								else
								{
									while(  redirect[next].redirect != -1) {
										next=redirect[next].redirect;
									}
									redirect[next].redirect=rj;
									//bcopy(bcdimsi, redirect[rj].imsi, 6);
									bcopy(bcdimsi, redirect[rj].imsi, MAX_BCD_IMSI_LEN);
									redirect[rj].offset=ci;
								}
								rj++;
							}
							
							ci++;
							
							curr_i++;
					}
					
					//数据库中数据均读取完，则返回
				  if(leave <= 0 ) {
				  	return ci;
				  }
				  
					leave = leave - MAX_EXTRACT_ROW;
					
					//每次读取设置的最大行数或剩余行数
   				if(leave > 0 ){
   					   fetch_row_num = MAX_EXTRACT_ROW;
   				} 
   				else 
 	 				{
 	 						 fetch_row_num = leave + MAX_EXTRACT_ROW;
 	 				}
 	 				
 	 				fetch_num = fetch_row_num;
 	 				//cout << "test0010 ci =" <<ci <<" fetch_row_num=" << fetch_row_num <<" fetch_num=" << fetch_num  <<endl;
      		rc = OCIStmtFetch(stmthp, errhp,(ub4) fetch_num, 0, 0);
		}
	}

	printf("in read_context rc=%d ci=%d,rj=%d \n",rc,ci,rj);
	
	return ci;
}


int read_physical_area(char *tablename, char *columnname)
{
	int rc=1;
	char errbuf[100];
  int  errcode;
	char sqlstring[128];
	char laccell[20];
	int rownum=0;

	if(strlen(tablename)<=0 || strlen(columnname)<=0 ) {
		printf(" tablename or columnname can not be null \n");
		exit(0);
	}
	
	strcpy (sqlstring, "SELECT distinct ");
	strcat(sqlstring, columnname);
	strcat(sqlstring, " FROM ");
	strcat(sqlstring, tablename);


  printf("in read_physical_area sqlstring=%s \n",sqlstring);

  
   /* Define the select list items */
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                                      
   /* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) laccell,
           (sword) 20, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);

   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);

   if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
      printf("Error in read_conflict\n");
      exit(8);
   }
   else
   {
      while (rc != OCI_NO_DATA) {             /* Fetch the remaining data */
      	  rownum++;
      	  //cout  << "in read_physical_area, physical_area:"  << laccell << std::endl;
      	  //m_physical_area.insert(laccell);
      		rc = OCIStmtFetch(stmthp, errhp, 1, 0, 0);
  		}
   }
   
	printf("in read_physical_area rc=%d 总记录数(ci)=%d \n",rc,rownum);

	/*
	set<string>::iterator 	m_pos_physical_area;
    for(m_pos_physical_area=physical_area.begin(); m_pos_physical_area!=physical_area.end(); ++m_pos_physical_area)
    {
        printf("[%s]\n", (*m_pos_physical_area).c_str());
    }
    printf("physical_area=[%d]\n", physical_area.size());
	*/

	return rc;
}


int read_pstn_area_info(char *tablename, char *columnname1, char *columnname2)
{
	int rc=1;
	char errbuf[100];
  int  errcode;
	char sqlstring[128];
	char area_code[10];
	int area_type=0;
	int rownum=0;

	if(strlen(tablename)<=0 || strlen(columnname1)<=0 || strlen(columnname2)<=0) {
		printf(" tablename or columnname can not be null \n");
		exit(0);
	}
	
	strcpy (sqlstring, "SELECT distinct ");
	strcat(sqlstring, columnname1);
	strcat(sqlstring, " , ");
	strcat(sqlstring, columnname2);
	strcat(sqlstring, " FROM ");
	strcat(sqlstring, tablename);

  printf("in read_pstn_area_info sqlstring=%s \n",sqlstring);

  
   /* Define the select list items */
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                                      
   /* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) area_code,
           (sword) 10, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);

		/* Define the select list items */
		rc = OCIDefineByPos(stmthp, &dfnp2, errhp, 2, (dvoid *) &area_type,
  	         sizeof(int), SQLT_INT, (dvoid *) 0, (ub2 *)0,
  	         (ub2 *)0, OCI_DEFAULT);
           
   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);

   if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
      printf("Error in read_conflict\n");
      exit(8);
   }
   else
   {
      while (rc != OCI_NO_DATA) {             /* Fetch the remaining data */
      	  rownum++;
      	  //printf("in read_pstn_area_info rownum=%d area_type=%d \n",rownum,area_type);
      	  m_pstn_area_info[atoi(area_code)] = area_type;
      	 // printf("in read_pstn_area_info rownum=%d area_type=%d m_pstn_area_info=%d \n",rownum,area_type,m_pstn_area_info[atoi(area_code)]);
      		rc = OCIStmtFetch(stmthp, errhp, 1, 0, 0);
  		}
   }
   
	printf("in read_pstn_area_info rc=%d 总记录数(ci)=%d \n",rc,rownum);

	return rc;
}


//int count_rows(char *tablename, char *cond)
int read_msisdn_info_num(char *tablename, char *columnname)
{
	int rc;
	int row_nums = 0;
  char sqlstring[128];
  char            errbuf[100];
  int             errcode;
   
	if(strlen(tablename)<=0 || strlen(columnname)<=0) {
		printf(" tablename or columnname can not be null \n");
		exit(0);
	}
	
	strcpy (sqlstring, "SELECT count( distinct ");
	strcat(sqlstring, columnname);
	strcat(sqlstring, ") FROM ");
	strcat(sqlstring, tablename);
	
  printf("in read_msisdn_info_num sqlstring=%s \n",sqlstring);
     
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                            
   /* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) &row_nums,
           sizeof(int), SQLT_INT, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
                      
   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);
 
  if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
   }
    
 	//printf("rowcounts: tablename:%s columnname=%s row_nums:%ld  \n",tablename,columnname,row_nums);
 	//printf("in read_msisdn_info_num total row_nums=%d \n",row_nums); 

	return row_nums;
}


int read_msisdn_info(char *tablename, char *columnname1, char *columnname2, char *columnname3)
{
	int rc=1;
	char errbuf[100];
  int  errcode;
	char sqlstring[128];
	char msisdn_prefix[10];
	char str_area_code[10];	
	int int_area_type=0;
	int rownum=0;
	
	if(strlen(tablename)<=0 || strlen(columnname1)<=0 || strlen(columnname2)<=0 || strlen(columnname3)<=0) {
		printf(" tablename or columnname can not be null \n");
		exit(0);
	}
	
	memset(sqlstring, '\0', sizeof(sqlstring)); 
	strcpy (sqlstring, "SELECT distinct ");
	strcat(sqlstring, columnname1);
	strcat(sqlstring, " , ");
	strcat(sqlstring, columnname2);
	strcat(sqlstring, " , ");
	strcat(sqlstring, columnname3);
	strcat(sqlstring, " FROM ");
	strcat(sqlstring, tablename);
	strcat(sqlstring, " order by ");
	strcat(sqlstring, columnname1);


  printf("in read_msisdn_info sqlstring=%s \n",sqlstring);

  
   /* Define the select list items */
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                                      
   /* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) msisdn_prefix,
           (sword) 10, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);

		/* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp2, errhp, 2, (dvoid *) str_area_code,
           (sword) 10, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
  	         
		/* Define the select list items */
		rc = OCIDefineByPos(stmthp, &dfnp3, errhp, 3, (dvoid *) &int_area_type,
  	         sizeof(int), SQLT_INT, (dvoid *) 0, (ub2 *)0,
  	         (ub2 *)0, OCI_DEFAULT);
           
   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);

   if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
      printf("Error in read_conflict\n");
      exit(8);
   }
   else
   {
      while (rc != OCI_NO_DATA) {             /* Fetch the remaining data */
      	  //m_pstn_area_info[atoi(area_code)] = area_type;
      	  char tmp[20];
					memset(tmp, '\0', sizeof(tmp)); 
					// 格式：号段（7位）+区号类型（1位）+区号代码（将“0”去掉，2-3位）
					// 举例：1352161@1@10   1352162@1@551
					sprintf(tmp, "%s@%d@%s", msisdn_prefix, int_area_type, str_area_code);
					//printf("rownum=[%d],tmp=[%s]\n", rownum,tmp);
					strcpy(m_msisdn_info[rownum], tmp);
					//printf("m_msisdn_info[%d]=[%s]\n", rownum,m_msisdn_info[rownum]);
      		rc = OCIStmtFetch(stmthp, errhp, 1, 0, 0);
      		rownum++;
  		}
   }
   
	printf("in read_msisdn_info total rownum=%d \n",rownum);

	return rc;
}


int read_spec_services(char *tablename, char *columnname, string& access_numbers)
{
	int rc=1;
	char errbuf[100];
  int  errcode;
	char sqlstring[128];
	char access_number[30];
	int rownum=0;

	if(strlen(tablename)<=0 || strlen(columnname)<=0) {
		printf(" tablename or columnname can not be null \n");
		exit(0);
	}
	
	memset(sqlstring, '\0', sizeof(sqlstring)); 
	strcpy (sqlstring, "SELECT distinct ");
	strcat(sqlstring, columnname);
	strcat(sqlstring, " FROM ");
	strcat(sqlstring, tablename);
	strcat(sqlstring, " order by ");
	strcat(sqlstring, columnname);


  printf("in read_spec_services sqlstring=%s \n",sqlstring);

  
   /* Define the select list items */
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                                      
   /* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) access_number,
           (sword) 30, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
           
   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);

   if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
      printf("Error in read_conflict\n");
      exit(8);
   }
   else
   {
      while (rc != OCI_NO_DATA) {             /* Fetch the remaining data */
      	
      		if(rownum == 0)
					{
						access_numbers.append(",");
					}		
    			
					access_numbers.append(access_number);
					access_numbers.append(",");
		
      	  rownum++;
					
      		rc = OCIStmtFetch(stmthp, errhp, 1, 0, 0);
  		}
   }
   
	printf("in read_spec_services 总记录数(rownum)=%d \n",rownum);
	printf("in access_numbers=[%s]\n", access_numbers.c_str());
	
	return rc;
}


int read_numbers_prefix_info_num(char *tablename, char *columnname)
{
	int rc;
	int numbers_prefix_row_nums = 0;
  char sqlstring[128];
  char            errbuf[100];
  int             errcode;
   
	if(strlen(tablename)<=0 || strlen(columnname)<=0) {
		printf(" tablename or columnname can not be null \n");
		exit(0);
	}
	
	strcpy (sqlstring, "SELECT distinct count(");
	strcat(sqlstring, columnname);
	strcat(sqlstring, ") FROM ");
	strcat(sqlstring, tablename);


  printf("in read_numbers_prefix_info_num sqlstring=%s \n",sqlstring);
     
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                            
   /* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) &numbers_prefix_row_nums,
           sizeof(int), SQLT_INT, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
                      
   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);
 
  if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
   }
    
	printf("in read_numbers_prefix_info_num 总记录数(numbers_prefix_row_nums)=%d \n",numbers_prefix_row_nums);

	return numbers_prefix_row_nums;
}


int read_numbers_prefix_info(char *tablename, char *columnname, string& numbers_prefixs)
{
	int rc=1;
	char errbuf[100];
  int  errcode;
	char sqlstring[128];
	char numbers_prefix[11];
	int rownum=0;

	if(strlen(tablename)<=0 || strlen(columnname)<=0) {
		printf(" tablename or columnname can not be null \n");
		exit(0);
	}
	
	memset(sqlstring, '\0', sizeof(sqlstring)); 
	strcpy (sqlstring, "SELECT distinct ");
	strcat(sqlstring, columnname);
	strcat(sqlstring, " FROM ");
	strcat(sqlstring, tablename);
	strcat(sqlstring, " order by ");
	strcat(sqlstring, columnname);

  printf("in read_spec_services sqlstring=%s \n",sqlstring);

  
   /* Define the select list items */
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                                      
   /* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) numbers_prefix,
           (sword) 11, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
           
   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);

   if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
      printf("Error in read_conflict\n");
      exit(8);
   }
   else
   {
      while (rc != OCI_NO_DATA) {             /* Fetch the remaining data */
					numbers_prefixs.append(numbers_prefix);
					numbers_prefixs.append(",");
		
      	  rownum++;
					
      		rc = OCIStmtFetch(stmthp, errhp, 1, 0, 0);
  		}
   }
   
	printf("in read_numbers_prefix_info total rownum=%d \n",rownum);
	
	// remove the last “,”
	numbers_prefixs.erase(numbers_prefixs.size()-1);
	printf("in numbers_prefixs=[%s]\n", numbers_prefixs.c_str());
	
	return rc;
}


int read_mobile_prefix_num(char *tablename, char *columnname, char *cond)
{
	int rc;
	int row_nums = 0;
  char sqlstring[128];
  char            errbuf[100];
  int             errcode;
   
	if(strlen(tablename)<=0 || strlen(columnname)<=0) {
		printf(" tablename or columnname can not be null \n");
		exit(0);
	}
	
	strcpy (sqlstring, "SELECT count(distinct ");
	strcat(sqlstring, columnname);
	strcat(sqlstring, ") FROM ");
	strcat(sqlstring, tablename);
	if(strlen(cond)>0) {
		strcat(sqlstring, " where ");
		strcat(sqlstring, cond);
	}

  printf("in read_mobile_prefix_num sqlstring=%s \n",sqlstring);
     
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                            
   /* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) &row_nums,
           sizeof(int), SQLT_INT, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
                      
   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);
 
  if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
   }
    
 	printf("in read_mobile_prefix_num 总记录数(mobile_prefix_nums)=%d \n",row_nums);

	return row_nums;
}


int read_mobile_prefix(char *tablename, char *columnname, char *cond)
{
	int rc=1;
	char errbuf[100];
  int  errcode;
	char sqlstring[128];
	char prefix_number[10];
	int int_prefix_type=0;
	int rownum=0;
	
	if(strlen(tablename)<=0 || strlen(columnname)<=0 ) {
		printf(" tablename or columnname can not be null \n");
		exit(0);
	}
	
	strcpy (sqlstring, "SELECT distinct ");
	strcat(sqlstring, columnname);
	strcat(sqlstring, " FROM ");
	strcat(sqlstring, tablename);
	if(strlen(cond)>0) {
		strcat(sqlstring, " where ");
		strcat(sqlstring, cond);
	}
	strcat(sqlstring, " ORDER BY ");
	strcat(sqlstring, columnname);
  printf("in read_mobile_prefix sqlstring=%s \n",sqlstring);

  
   /* Define the select list items */
   rc = OCIStmtPrepare(stmthp, errhp,  (text *) sqlstring,
           (ub4) strlen(sqlstring), (ub4) OCI_NTV_SYNTAX, (ub4) OCI_DEFAULT);
                                      
   /* Define the select list items */
   rc = OCIDefineByPos(stmthp, &dfnp, errhp, 1, (dvoid *) prefix_number,
           (sword) 10, SQLT_STR, (dvoid *) 0, (ub2 *)0,
           (ub2 *)0, OCI_DEFAULT);
  	         
		/* Define the select list items */
		rc = OCIDefineByPos(stmthp, &dfnp2, errhp, 2, (dvoid *) &int_prefix_type,
  	         sizeof(int), SQLT_INT, (dvoid *) 0, (ub2 *)0,
  	         (ub2 *)0, OCI_DEFAULT);
           
   /* Execute the SQL statment */
   rc = OCIStmtExecute(svchp, stmthp, errhp, (ub4) 1, (ub4) 0,
           (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, OCI_DEFAULT);

   if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
      printf("Error in read_conflict\n");
      exit(8);
   }
   else
   {
      while (rc != OCI_NO_DATA) {             /* Fetch the remaining data */
					if(strlen(prefix_number) > 10)
					{
						printf("表[%s]中[%s]字段长度不能大于10字节\n", tablename, columnname);
						printf("程序退出！\n");
						
						exit(-1);
					}
					strcpy(mobile_prefix_area[rownum], prefix_number);
					mobile_prefix_type[rownum] = int_prefix_type;
		
      		rc = OCIStmtFetch(stmthp, errhp, 1, 0, 0);
      		
      		rownum++;
  		}
   }

	return rownum;
}


int load_table(char *filename, char *tablename)
{
	int             rc=1;
	 printf("load_table rc=%d \n",rc);
	return rc;
}


int close_db(void)
{
	int             rc;
   
   rc = OCILogoff(svchp, errhp);                           /* Disconnect */
   rc = OCIHandleFree((dvoid *) stmthp, OCI_HTYPE_STMT);    /* Free handles */
   rc = OCIHandleFree((dvoid *) svchp, OCI_HTYPE_SVCCTX);
   rc = OCIHandleFree((dvoid *) errhp, OCI_HTYPE_ERROR);
	 printf("close database rc=%d \n",rc);
	return rc;
}

int connect_db(char *db, char *user, char *pass)
{
	char            errbuf[100];
  int             errcode;
	int             rc;
   
  printf("in connect_db,db=[%s] user=[%s],pass=[%s]\n",db,user,pass);
      
   /* Initialize OCI evironment*/
   rc = OCIEnvCreate((OCIEnv **) &envhp,OCI_DEFAULT,(dvoid *)0,
          (dvoid * (*)(dvoid *, size_t)) 0,
          (dvoid * (*)(dvoid *, dvoid *, size_t))0,
          (void (*)(dvoid *, dvoid *)) 0,      
          (size_t) 0, (dvoid **) 0);
  
   /* Initialize handles */
   rc = OCIHandleAlloc( (dvoid *) envhp, (dvoid **) &errhp, OCI_HTYPE_ERROR,
           (size_t) 0, (dvoid **) 0);
   rc = OCIHandleAlloc( (dvoid *) envhp, (dvoid **) &svchp, OCI_HTYPE_SVCCTX,
           (size_t) 0, (dvoid **) 0);

   /* Connect to database server */
   rc = OCILogon(envhp, errhp, &svchp, (text *) user, strlen(user) * sizeof(char), (text *) pass, strlen(pass) * sizeof(char), (text *) db,strlen(db) * sizeof(char));
   if (rc != OCI_SUCCESS) {
      OCIErrorGet((dvoid *)errhp, (ub4) 1, (text *) NULL, &errcode, (text *) errbuf, (ub4) sizeof(errbuf), OCI_HTYPE_ERROR);
      printf("Error - %.*s\n", 512, errbuf);
      exit(8);
   }
   else
   {
    printf("Connect to %s successful!\n",db); 
   }

   /* Allocate and prepare SQL statement */
   rc = OCIHandleAlloc((dvoid *) envhp, (dvoid **) &stmthp,
           OCI_HTYPE_STMT, (size_t) 0, (dvoid **) 0);

	return rc;
}
