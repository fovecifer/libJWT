test: 
		gcc test.c cJSON.c libJWT.c -g -o test -lssl -lcrypto -lm -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
clean:
		rm -f test
