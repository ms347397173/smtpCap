/*
 *Author: ms
 *Date: 2017/3/11
 *Summary: capture and analyze SMTP protocol 
 *
 */

#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<nids.h>

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

}smtp_request_state;

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
typedef struct mail_data_type
{
	//EHLO
	char hostname[1024];
	
	//AUTH
	char username[1024];  
	char password[1024];
	char auth_type[32];

	//MAIL
	char from[1024];

	//RCPT
	char sendto[256][1024];
	
	//DATA
	char subject[1024];
	char date[64];
	char user_agent[256];
	char main_body[65535];



}mail_data_type;


/*
 *  Summary: analyze sended smtp packet from buffer
 *  param:
 *		buf : buf from nids server data
 *		size : data's size
 */

void smtp_request_parser(char * buf,size_t size)
{
	char * cur=buf;  //a pointer for parser
	char command[5];  //command have 4 characters
	command[4]=0;  //"C" type string '\0'

	memcpy(command,buf,4);
	cur=buf+5;   //jump command(4)+1

	if(strcmp(command,"EHLO")==0)
	{
		smtp_request_state=EHLO;
	}
	else if(strcmp(command,"AUTH")==0)
	{
		smtp_request_state=AUTH;
	}
	else if(strcmp(command,"MAIL")==0)
	{
		smtp_request_state=MAIL;
	}
	else if(strcmp(command,"RCPT")==0)
	{
		smtp_request_state=RCPT;
	}
	else if(strcmp(command,"DATA")==0)
	{
		smtp_request_state=DATA;
	}
	else if(strcmp(command,"QUIT")==0)
	{
		smtp_request_state=QUIT;
	}
	else if(strcmp(command,"RSET")==0)
	{
		smtp_request_state=RSET;
	}
	else
	{
		//no support
		smtp_request_state=UNKOWN;
		return;
	}


}

/*
 *  Summary: analyze received smtp packet from buffer
 *  param:
 *		buf : buf from nids client data
 *		size : data's size
 */
void smtp_reply_parser(char * buf,size_t size)
{
}


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

			fprintf(stdout,"%s mail transport established\n",buf);
		
		}
		return ;
	}

	// connection has been closed 
	if(a_tcp->nids_state == NIDS_CLOSE)
	{
		fprintf(stdout,"%s closeing\n",buf);
	
	    a_tcp->client.collect--;
	    a_tcp->server.collect--;
	    a_tcp->server.collect_urg--;
        a_tcp->client.collect_urg--;

		return;
	}

    // connection has been closed by RST
	if (a_tcp->nids_state == NIDS_RESET)
    {
        fprintf (stdout, "%s reset\n", buf);
        return;
    }

	//receiveing data
	if(a_tcp->nids_state == NIDS_DATA)
	{
		struct half_stream * hlf;

		if(a_tcp->server.count_new_urg)
		{
			printf("server urg data\n");
			return ;
		}
		if(a_tcp->server.count_new)
		{
			printf("send data:%s\n",a_tcp->server.data);
			return ;
		}
		if(a_tcp->client.count_new_urg)
		{
			 printf("client urg data\n");
             return ;
		}
		if(a_tcp->client.count_new)
		{
			printf("received data:%s\n",a_tcp->client.data);
			return ;
		}

	}


}



int main()
{
	nids_params.device="eth1";

	if(!nids_init())
	{
		fprintf(stdout,"%s\n",nids_errbuf);
		exit(1);
	}

	nids_register_tcp(tcp_callback);

	nids_run();

	return 0;

}

