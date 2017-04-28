test: test.c
		gcc -std=gnu99 test.c cJSON.h cJSON.c libJWT.c -g -o test -lssl -lcrypto -lm
clean:
		rm -f test
