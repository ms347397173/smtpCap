NO_WARN=-Wall
CC=g++

BASE64=base64.c
TEXTTOOLS=text_tools.c


DEBUG=-g

NIDSLIB=-lnids
NETLIB=-lnet
PCAPLIB=-lpcap
CURLLIB=-lcurl
NSLLIB=-lnsl
LIBS=$(NIDSLIB) $(NETLIB) $(PCAPLIB) $(NSLLIB) $(CURLLIB) -lgthread-2.0 $(BASE64) $(TEXTTOOLS)


all:smtpCap

debug:smtpCap.cpp
	$(CC) $(DEBUG) $(NO_WARN) -o smtpCap $^ $(LIBS)

smtpCap:smtpCap.cpp
	$(CC) $(NO_WARN) -o $@ $^ $(LIBS)

base64:test_base64

test_base64:test_base64.c
	$(CC) $(NO_WARN) -o $@ $^ $(BASE64)

clean:
	rm -f smtpCap test_base64
