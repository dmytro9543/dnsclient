all:
	gcc my-dns-client.c -g -Wall -o my-dns-client

clean:
	rm my-dns-client
