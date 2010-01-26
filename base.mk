all:	clean uwsgi

uwsgi:  utils.o protocol.o socket.o pymodule.o spooler.o logging.o main.o
	$(CC) $(LD_FLAGS) utils.o protocol.o socket.o spooler.o logging.o pymodule.o main.o -o $(PROGRAM)

utils.o: utils.c
	$(CC) -c $(CFLAGS) utils.c

protocol.o: protocol.c
	$(CC) -c $(CFLAGS) protocol.c

socket.o: socket.c
	$(CC) -c $(CFLAGS) socket.c

spooler.o: spooler.c
	$(CC) -c $(CFLAGS) spooler.c

logging.o: logging.c
	$(CC) -c $(CFLAGS) logging.c

pymodule.o: uwsgi_pymodule.c
	$(CC) -c $(CFLAGS) -o pymodule.o uwsgi_pymodule.c

main.o: uwsgi.c
	$(CC) -c $(CFLAGS) -o main.o uwsgi.c
        
clean:
	rm -f utils.o protocol.o socket.o pymodule.o spooler.o logging.o main.o
