
#include"base64.h"

const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char base64_decode_array[256] =
{
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,62,255,255,255,63,
	52,53,54,55,56,57,58,59,
	60,61,255,255,255,254,255,255,
	255,0,1,2,3,4,5,6,
	7,8,9,10,11,12,13,14,
	15,16,17,18,19,20,21,22,
	23,24,25,255,255,255,255,255,
	255,26,27,28,29,30,31,32,
	33,34,35,36,37,38,39,40,
	41,42,43,44,45,46,47,48,
	49,50,51,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255
};
/********************************************
 * Summary: base64 encode
 * Param:
 *		dest:encoded data
 *		src:source data
 *		src_length:source data length
 *Return:
 *		return dest's memory address
 ********************************************/
const unsigned char * base64_encode(unsigned char * dest,const unsigned char * src,size_t src_length)
{
	int i=0,j=0;
	unsigned char ch;
	for(i=0,j=0;i<src_length;i+=3)
	{
		// first
		ch=(src[i]>>2);
		ch&=(unsigned char)0x3F;
		dest[j++]=base64char[(int)ch];

		// second
		ch=((unsigned char)(src[i]<<4))&((unsigned char)0x30);
		if(i+1>=src_length)
		{
			dest[j++]=base64char[(int)ch];
			dest[j++]='=';
			dest[j++]='=';
			break;
		}

		ch|=((unsigned char)(src[i+1]>>4)&(unsigned char)0x0F);
		dest[j++]=base64char[(int)ch];
		
		// third
		ch=((unsigned char)src[i+1]<<2)&((unsigned char)0x3C);
		if(i+2>=src_length)
		{
			dest[j++]=base64char[(int)ch];
			dest[j++]='=';
			break;
		}

		ch|=((unsigned char)(src[i+2]>>6))&((unsigned char)0x03);

		dest[j++]=base64char[(int)ch];

		//fourth
		ch=(unsigned char)(src[i+2])&((unsigned char)0x3F);
		dest[j++]=base64char[(int)ch];

	}
	dest[j]='\0';
	return dest;
}

/********************************************
 * Summary: base64 decode
 * Param:
 *		dest:decoded data
 *		src:source data
 *		src_length:source data length
 *Return:
 *		return dest's memory address
 ********************************************/
const unsigned char * base64_decode(unsigned char * dest,const unsigned char * src,size_t src_length)
{
	unsigned char str[4];
	int i=0;
	int j=0;
	for(i=0;i<src_length;i+=4)
	{
		//first char
		str[0]=base64_decode_array[(int)src[i]];
		str[1]=base64_decode_array[(int)src[i+1]];
		dest[j++]=(str[0]<<2)+(str[1]>>4);

		//second char
		if(src[i+2]!='=') 
		{
			str[2]=base64_decode_array[(int)src[i+2]];
			dest[j++]=((str[1]&0x0F)<<4)+(str[2]>>2);
		}

		//third char
		if(src[i+3]!='=')
		{
			str[3]=base64_decode_array[(int)src[i+3]];
			dest[j++]=((str[2]&0x03)<<6)+(str[3]&0x3F);
		}
	}
	dest[j]='\0';
	return dest;
}
