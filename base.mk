include config

all:	clean uwsgi

uwsgi:  utils.o protocol.o socket.o pymodule.o spooler.o logging.o snmp.o wsgihandlers.o basehandlers.o main.o
	$(CC) $(LD_FLAGS) -lpthread utils.o protocol.o socket.o spooler.o logging.o snmp.o pymodule.o wsgihandlers.o basehandlers.o main.o -o $(PROGRAM)

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

snmp.o: snmp.c
	$(CC) -c $(CFLAGS) snmp.c

pymodule.o: uwsgi_pymodule.c
	$(CC) -c $(CFLAGS) -o pymodule.o uwsgi_pymodule.c

basehandlers.o: uwsgi_handlers.c
	$(CC) -c $(CFLAGS) -o basehandlers.o uwsgi_handlers.c

wsgihandlers.o: wsgi_handlers.c
	$(CC) -c $(CFLAGS) -o wsgihandlers.o wsgi_handlers.c

main.o: uwsgi.c
	$(CC) -c $(CFLAGS) -o main.o uwsgi.c
        
clean:
	rm -f utils.o protocol.o socket.o pymodule.o spooler.o logging.o snmp.o wsgihandlers.o basehandlers.o main.o
