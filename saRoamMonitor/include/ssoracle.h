#ifndef _SSORACLE_H
#define _SSORACLE_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <oci.h>
#include <oratypes.h>

#include <iostream>

/* LDA and CDA struct declarations */
#include <ocidfn.h>

#ifdef __STDC__
#include <ociapr.h>
#else
#include <ocikpr.h>
#endif

#include <ocidem.h>


#include "sspublic.h"
#include "sscontext.h"

using namespace std;


//=================================================

//set<string>::iterator 	m_pos_physical_area;

//extern set<string> 				m_physical_area;
//=================================================

extern char						**m_physical_area;

extern int m_pstn_area_info[1000];

extern char	**m_msisdn_info;
extern int	msisdn_num;

extern char	**m_numbers_prefix_info;
extern int	numbers_prefix_info_num;

extern int	mobile_prefix_type[MAX_MOBILE_PREFIX_NUM];
extern int	mobile_prefix_num;
extern char	**mobile_prefix_area;


int rowcounts(char *tablename);
int count_rows(char *tablename, char *cond);
int read_conflict(char *tablename, char *cond);
int read_context(char *tablename, char *cond);
int read_physical_area(char *tablename, char *columnname);
int load_table(char *filename, char *tablename);
int clear_table(char *tablename);
int connect_db(char *db, char *user, char *pass);
int close_db(void);

int read_pstn_area_info(char *tablename, char *columnname1, char *columnname2);

int read_msisdn_info_num(char *tablename, char *columnname);
int read_msisdn_info(char *tablename, char *columnname1, char *columnname2, char *columnname3);

int read_spec_services(char *tablename, char *columnname, string& access_numbers);

int read_numbers_prefix_info_num(char *tablename, char *columnname);
int read_numbers_prefix_info(char *tablename, char *columnname, string& numbers_prefixs);

int read_mobile_prefix_num(char *tablename, char *columnname, char *cond);
int read_mobile_prefix(char *tablename, char *columnname, char *cond);

#endif
