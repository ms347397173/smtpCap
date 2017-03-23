
#include<stddef.h>
#include<string.h>
#include<malloc.h>
#ifndef __OUT_PARAM__
#define __OUT_PARAM__
#endif
/***********************************************
 * Summary:get a line from buf
 * Param:
 *		buf : src string
 *		size : max length
 *		ret : dest string
 * Return:
 *		get char number
 ************************************************/
int get_line(unsigned char *buf,size_t size,unsigned char* ret)
{
	unsigned char * src=buf;
	unsigned char * dst=ret;
	int i=0;

	//jump initial \r & \n
	for(;(*src)=='\r'||(*src)=='\n';++src)
	{}
	
	//copy
	for(;(*src)!='\r'&&(*src)!='\n'&&size>0;++src)
	{
		*dst=*src;
		++dst;
		--size;
		++i;
	}
	*dst='\0';
	return i;
}

/************************************************
 * Summary:search first specified char of buf
 * Param:
 *		buf:src buf
 *		size:buf size
 * Return:
 *		return blank index,if no find return -1
 ************************************************/
int find_char(unsigned char * buf,size_t size,unsigned char ch)
{
	for(int i=0;i<size;++i)
	{
		if(buf[i]==ch)
		{
			return i;
		}
	}
	return -1;
}

/**************************************************************************************************
 * Summary:accroding to key,read value from buf,,the format is [key: value],the format has a space
 * Param:
 *		buf: src string
 *		size: buf's size
 *		key_str: key string
 *		value_str: value string ,the parament is out parament
 **************************************************************************************************/
unsigned char * read_info(unsigned char * buf,size_t size,unsigned char * key_str,__OUT_PARAM__ unsigned char * value_str)
{
	int chars=0;

	unsigned char * ex_key_str=NULL;
	char * str=NULL;
	//begining of the buf,not \r\n
	if(strncasecmp((char *)buf,(char *)key_str,strlen((char *)key_str))==0)
	{
		str=(char *)buf+strlen((char *)key_str)+2;
		chars=get_line((unsigned char *)str,size-(size_t)((unsigned char *)str-buf),value_str);
	}
	else
	{
    	//not begining
    	int key_str_length=strlen((const char *)key_str)+1;
    	int ex_key_str_length=key_str_length+2;
    	ex_key_str=(unsigned char *)malloc(ex_key_str_length); //"\r\n[key_str]\0"
		memset(ex_key_str,0,ex_key_str_length);
    	ex_key_str[0]='\r';
    	ex_key_str[1]='\n';
    	memcpy(ex_key_str+2,key_str,strlen((const char *)key_str));
    	ex_key_str[ex_key_str_length-1]='\0';
    
    	str=strcasestr((char *)buf,(char *)ex_key_str);
    	if(str==NULL)
    	{
    		free(ex_key_str);
    		ex_key_str=NULL;
    		return NULL;
    	}
    
    	str+=key_str_length-1+2+2;  //has a space and ':' and '\r\n' 
    	
    	chars=get_line((unsigned char *)str,size-(size_t)((unsigned char *)str-buf),value_str);
    
		//free memory
		free(ex_key_str);
		ex_key_str=NULL;
	}
	//if the next line not have filed , the line of the value_str 
	//example: 
	/**************************************************************
	 *User-Agent: mozilla .....\r\n
	 *thunderbird 1.2\r\n         //this line not have filed ,the line of the User-Agent
	 *
	 *
	 * *************************************************************/
	str=str+chars+2/*\r\n*/;
	if(*str==' ')  //the begining of the line is space , the line of the up line
	{
		get_line((unsigned char *)str,size-(size_t)((unsigned char *)str-buf),value_str+chars);
	}

	return value_str;
}
