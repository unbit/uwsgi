all:	clean uwsgi

uwsgi:  utils.o socket.o pymodule.o spooler.o main.o
	$(CC) $(LD_FLAGS) utils.o socket.o spooler.o pymodule.o main.o -o $(PROGRAM)

utils.o: utils.c
	$(CC) -c $(CFLAGS) utils.c

socket.o: socket.c
	$(CC) -c $(CFLAGS) socket.c

spooler.o: spooler.c
	$(CC) -c $(CFLAGS) spooler.c

pymodule.o: uwsgi_pymodule.c
	$(CC) -c $(CFLAGS) -o pymodule.o uwsgi_pymodule.c

main.o: uwsgi.c
	$(CC) -c $(CFLAGS) -o main.o uwsgi.c
        
clean:
	rm -f utils.o socket.o pymodule.o spooler.o main.o
