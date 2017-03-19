enum smtp_request_type
{
	UNKOWN,
	EHLO,
	AUTH,
	MAIL,
	RCPT,
	DATA,
	QUIT,
	RSET,
	//the follow type is source in << TCP/IP Illustrated Volume 1>>,those may no need 
	VRFY,
	NOOP,
	TURN

};

//this is meaningless 
/*
enum smtp_reply_type
{
	EHLO_OK,  //250
	AUTH_OK,  //235
	MAIL_OK,  //250
	RCPT_OK,  //250
	DATA_OK,  //
}smtp_reply_state;

*/
//these array's size should reconsider,its too long now
// no mem align
typedef struct mail_data_type
{
	//source port is local byte order
	unsigned short source_port;  //dest port is fixed(25)   

	//state
	smtp_request_type smtp_request_state;

	//EHLO
	unsigned char hostname[128];
	
	//AUTH
	unsigned char username[128];  
	unsigned char password[128];
	unsigned char auth_type[32];

	//MAIL
	unsigned char from[128];

	//RCPT
	int sendto_num;
	unsigned char sendto[32][128];  //no greater than 32 user
	
	//DATA
	unsigned char subject[1024];
	unsigned char date[64];
	unsigned char user_agent[64];
	unsigned char main_body[65535];   //the content isn't base64 code ,is being decoded
	unsigned char attachment_name[16][128];  

}mail_data_type;


//this structure save config infomation for smtpCap
typedef struct config_info_type
{
	int server_ip;
	unsigned short server_port;
}config_info_type;
