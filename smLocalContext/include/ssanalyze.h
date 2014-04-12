#ifndef _SSANALYZE_H
#define _SSANALYZE_H

extern Analyze ana;

extern pthread_mutex_t		filtrate_mutex;
extern pthread_mutex_t		pthread_init_mutex;
extern pthread_mutex_t		pthread_logfile_mutex;

extern int field_imsi_num;
extern int field_event_type_num;
extern int field_time_stamp_num;
extern int field_duration_num;
extern int field_lac_id_num;
extern int field_ci_id_num;
extern int field_cause_num;
extern int field_other_party_num;

extern int field_local_prov_flag_num;
extern int field_prov_code_num;
extern int field_city_code_num;


typedef struct decode_map
{
	char		field_name[50];
	int			field_id;

    friend bool operator==(const decode_map& firstVal, const decode_map& secondVal) ;
    friend bool operator<(const decode_map& firstVal, const decode_map& secondVal);
}DECODE_MAP;


void *consume( void *arg);
int loadDB(int ruleid);
int WriteResult(int ruleid, char *src);
int GetResultStr(Context *rec, int time_flag, char *str_result_tmp);
int WriteRule(int ruleid, char *src);
void ExecCmd(const char *cmd);

void testFind(char *imsi);
void testGet( char *imsi);

int update_user_info(char *word[], Context *rec, char *str_result_tmp);
//int update_user_resident_time();

int update_user_other_numbers(char* event_type, char *opp_num, char *opp_num_cleanout, Context *rec, char *str_result_tmp);

void read_decode_info();

int read_event_type();

void read_event_type_wld();

void read_nonparticipant_data();

int  find_event_type(char *event_type);


int read_physical_area_info();
int  find_physical_area(char *physical_area);


int read_area_info();
int  find_msisdn_area_info(char *msisdn);

void update_other_party_area(int action_type, char *msisdn_cleanout, char * opp_num_cleanout, Context *rec);


int read_spec_services_info();
int find_spec_services_info(char *access_number);

char* numbers_cleanout(char *numbers);

int read_prefix_info();
int  find_prefix_info(char *numbers);

#endif
