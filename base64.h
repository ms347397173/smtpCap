/**********************************
 * Summary:base64 libary
 * Author:ms
 * Date:2017/3/18
 ********************************/
#include<stddef.h>
const unsigned char * base64_encode(unsigned char * dest,const unsigned char * src,size_t src_length);

const unsigned char * base64_decode(unsigned char * dest,const unsigned char * src,size_t src_length);

