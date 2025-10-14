EXES=my_strcmp.so check_serial

all: $(EXES)

my_strcmp.so: my_strcmp.c
	gcc -shared -fPIC my_strcmp.c -ldl -o my_strcmp.so

check_serial: check_serial.c
	gcc -z now -o check_serial check_serial.c

clean:
	rm -f $(EXES)
