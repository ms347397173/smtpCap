#include<curl/curl.h>
#include<stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include<unistd.h>
#include<errno.h>
size_t read_callback(void * ptr,size_t size,size_t nmemb,void * stream)
{
	curl_off_t nread;
	size_t ret_num=fread(ptr,size,nmemb,stream);
	nread=(curl_off_t)ret_num;
	fprintf(stderr, "*** We read %" CURL_FORMAT_CURL_OFF_T
					" bytes from file\n", nread);

	return ret_num;
}

#define LOCAL_FILE "./Makefile"
#define REMOTE_URL "ftp://192.168.140.1/MAKEFILE.txt"
int main()
{
	CURL  * curl;
	FILE * fp=NULL;
	CURLcode res;
	curl_off_t fsize;
	struct stat file_info;
	struct curl_slist* headerlist=NULL;

	/* get the file size of the local file */ 
	if(stat(LOCAL_FILE, &file_info)) 
	{
		printf("Couldnt open '%s': %s\n", LOCAL_FILE, strerror(errno));
		return -1;
	}
	fsize = (curl_off_t)file_info.st_size;
	printf("Local file size: %" CURL_FORMAT_CURL_OFF_T " bytes.\n", fsize);

	fp=fopen(LOCAL_FILE,"rb");
	if(!fp)
	{
		printf("open file faild\n");
		return -1;
	}

	/* In windows, this will init the winsock stuff */ 
	curl_global_init(CURL_GLOBAL_ALL);
	   
	//easy init
	curl=curl_easy_init();
	if(!curl)
	{
		perror("curl init failed\n");
		return -1;
	}

	curl_easy_setopt(curl,CURLOPT_READFUNCTION,read_callback);
	
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	
	curl_easy_setopt(curl, CURLOPT_URL, REMOTE_URL);
	curl_easy_setopt(curl, CURLOPT_READDATA, fp);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,(curl_off_t)fsize);
	res = curl_easy_perform(curl);
	if(res!=CURLE_OK)
	{
		printf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
	}

    fclose(fp); /* close the local file */ 
    curl_global_cleanup();
	return 0;
}
