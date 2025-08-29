CC = gcc
CFLAGS = -Wall -g
LIBS = -lssl -lcrypto -lpthread

all: client kdc prnsrv

client: client.c
	$(CC) $(CFLAGS) -o client client.c $(LIBS)
#$(LIBS)

kdc: kdc.c
	gcc -Wall -g -o kdc kdc.c -I/usr/local/include -L/usr/local/lib $(LIBS) 

#$(LIBS)

prnsrv: prnsrv.c
	$(CC) $(CFLAGS) -o prnsrv prnsrv.c $(LIBS) -lhpdf

clean:
	rm -f client kdc prnsrv *.o
