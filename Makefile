NO_WARN=-Wall
CC=gcc

DEBUG=-g

NIDSLIB=-lnids
NETLIB=-lnet
PCAPLIB=-lpcap
LIBS=$(NIDSLIB) $(NETLIB) $(PCAPLIB) -lnsl -lgthread-2.0


all:smtpCap

debug:smtpCap
	$(CC) $(DEBUG) $(NO_WARN) -o smtpCap $^ $(LIBS)

smtpCap:smtpCap.c
	$(CC) $(NO_WARN) -o $@ $^ $(LIBS)


clean:
	rm -f smtpCap
