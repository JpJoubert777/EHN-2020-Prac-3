main: main.o RC4.o rsakeygen.o rsaencrypt.o rsadecrypt.o 
	gcc -o main main.o RC4.o rsakeygen.o rsaencrypt.o rsadecrypt.o  -lgmp

rsaencrypt: rsaencrypt.o 
	gcc -o rsaencrypt rsaencrypt.o -lgmp

rsadecrypt: rsadecrypt.o 
	gcc -o rsadecrypt rsadecrypt.o -lgmp

rsakeygen: rsakeygen.o RC4.o 
	gcc -o rsakeygen rsakeygen.o RC4.o -lgmp

RC4: RC4.o
	gcc -o RC4 RC4.o

main.o: main.c
	gcc -c main.c

rsaencrypt.o: rsaencrypt.c
	gcc -c rsaencrypt.c

rsadecrypt.o: rsadecrypt.c
	gcc -c rsadecrypt.c

rsakeygen.o: rsakeygen.c
	gcc -c rsakeygen.c

RC4.o: RC4.c
	gcc -c RC4.c







