#include"base64.h"
#include<string.h>
#include<stdio.h>
unsigned char buf[128];
unsigned char str[]={"ms347397173"};
unsigned char buf2[128];	

void test_encode()
{
	const unsigned char * p=base64_encode(buf,str,sizeof(str));
	printf("%s\n",p);
	
}

void test_decode()
{
	const unsigned char * p=base64_decode(buf2,buf,strlen((char *)buf));
	printf("%s\n",p);
}

int main()
{
	test_encode();
	test_decode();
	return 0;
}
