/************************************************
 *Author: ms
 *Date: 2017/3/11
 *Summary: capture and analyze SMTP protocol 
 *
 ***********************************************/

#define __DEBUG__  //use __TRACE__ macro
#include"Trace.h"

#include"smtp_type.h"

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

//global vars
list<mail_data_type> g_mail_data_list;
config_info_type g_config_info;

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

/***************************************************
 * Summary:find element from list
 * Param:
 *		source_port:local host port	
 *Return:
 *		return matched element's iterator ,no matched return end()
 *************************************************/
list<mail_data_type>::iterator find_element_from_list(unsigned short source_port)
{
	list<mail_data_type>::iterator it=g_mail_data_list.begin();
	for(;it!=g_mail_data_list.end();++it)
	{
		if(it->source_port==source_port)
		{
			break;
		}
	}
	return it;
}

/***********************************************
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

	fclose(fp);
	return 0;
}

/*********************************
 * Summary: thread entry
 * Param:
 *		arg: is type of (mail_data_type*) ,pointer of sended data
 *
 * */
void * thread_start(void * arg)
{
	mail_data_type* data= (mail_data_type*)arg;
	
	//sock conn
	struct sockaddr_in server_address;
	memset(&server_address,0,sizeof(server_address));
	server_address.sin_family=AF_INET;
	server_address.sin_addr.s_addr=g_config_info.server_ip;
	server_address.sin_port=g_config_info.server_port;

	int sock=socket(PF_INET,SOCK_STREAM,0);
	if(sock<0)
	{
		exit(1);
	}

	if(connect(sock,(struct sockaddr *)&server_address,sizeof(server_address))<0)
	{
		__TRACE__("connection failed!\n");
		close(sock);
		exit(2);
	}
	
	int ret=send(sock,data,sizeof(mail_data_type),0);
	if(ret<=0)
	{
		close(sock);
		exit(3);
	}
	__TRACE__("send success\n");

	close(sock);
}

/**************************************************
 * Summary:send object to server
 * Param:
 *		it:list's iterator
 * Return:
 *		0:SUCCESS
 *		-1:Failed
 *************************************************/
int send_data_to_server(list<mail_data_type>::iterator it)
{

	int ret;
	pthread_t tid;
	if(it!=g_mail_data_list.end())
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
 *		it: g_mail_data_list's iterator
 *		buf : buf from nids server data
 *		size : data's size
 ***********************************************************/
void smtp_request_parser(list<mail_data_type>::iterator it,char * buf,size_t size)
{
	char * cur=buf;  //a pointer for parser
	char command[5];  //command have 4 characters
	command[4]=0;  //"C" type string '\0'

	memcpy(command,buf,4);
	cur=buf+5;   //jump command(4)+1

    if(it==g_mail_data_list.end())
	{
		return;
	}

	if(strcmp(command,"EHLO")==0)
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
	}
	else if(strcmp(command,"QUIT")==0)
	{
		it->smtp_request_state=QUIT;
	}
	else if(strcmp(command,"RSET")==0)
	{
		it->smtp_request_state=RSET;
	}
	else
	{
		//no support
		it->smtp_request_state=UNKOWN;
		return;
	}


}

/**************************************************************
 *  Summary: analyze received smtp packet from buffer
 *  param:
 *		it : list's iterator
 *		buf : buf from nids client data
 *		size : data's size
 ***************************************************************/
void smtp_reply_parser(list<mail_data_type>::iterator it,char * buf,size_t size)
{
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
			g_mail_data_list.resize(g_mail_data_list.size()+1);
			g_mail_data_list.back().source_port=a_tcp->addr.source;
			
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
		list<mail_data_type>::iterator it=find_element_from_list(a_tcp->addr.source);
		
		//send object to server
        if(it!=g_mail_data_list.end())
		{
			send_data_to_server(it);
		}
		//delete object from list
		g_mail_data_list.erase(it);

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
		list<mail_data_type>::iterator it=find_element_from_list(a_tcp->addr.source);
		g_mail_data_list.erase(it);

		return;
	}


	//receiveing data
	if(a_tcp->nids_state == NIDS_DATA)
	{
		list<mail_data_type>::iterator it=find_element_from_list(a_tcp->addr.source);
		
		if(it==g_mail_data_list.end())
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
			__TRACE__("send data:%s\n",a_tcp->server.data);
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
			__TRACE__("received data:%s\n",a_tcp->client.data);	
			smtp_reply_parser(it,a_tcp->server.data,a_tcp->server.count_new);
			return ;
		}

	}


}



int main()
{

	if(read_config_file())
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

