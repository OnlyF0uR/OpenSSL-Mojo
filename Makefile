all: call_functions libfunctions.a run

libfunctions.a: openssl/functions.c
	gcc -static -c openssl/functions.c -o libfunctions.a

call_functions: main.mojo libfunctions.a
	./scripts/mojoc main.mojo -Slibfunctions.a -lssl -lcrypto -o app

run: FORCE app
	./app

clean:
	rm -f libfunctions.a app

FORCE: