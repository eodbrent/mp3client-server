CC := gcc
CFLAGS := -Wall -Wextra -I/usr/local/opt/openssl/include
LDFLAGS := -L/usr/local/opt/openssl/lib -lssl -lcrypto -pthread
LIBS := -lao -lmpg123

all: ssl-mp3client ssl-mp3server

ssl-mp3client: ssl-mp3client.o playaudio.o
        $(CC) $(CFLAGS) -o ssl-mp3client ssl-mp3client.o $(LDFLAGS) $(LIBS)

ssl-mp3server: ssl-mp3server.o
        $(CC) $(CFLAGS) -o ssl-mp3server ssl-mp3server.o $(LDFLAGS)

ssl-mp3client.o: ssl-mp3client.c
        $(CC) $(CFLAGS) -c ssl-mp3client.c

ssl-mp3server.o: ssl-mp3server.c
        $(CC) $(CFLAGS) -c ssl-mp3server.c

playaudio.o: playaudio.c
        $(CC) $(CFLAGS) -c playaudio.c

clean:
        rm -f ssl-mp3client ssl-mp3client.o ssl-mp3server ssl-mp3server.o playaudio.o
