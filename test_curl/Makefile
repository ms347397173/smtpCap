CC=gcc

all:test_ftp_put

test_ftp_put:test_ftp_put.c
	$(CC) -o $@ $^ -lcurl

clean:
	rm -rf test_ftp_put
