/* 
        
    *** uWSGI ***

    Copyright 2009 Unbit S.a.s.
        
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.


Compile on Linux 2.6
gcc -o uwsgi -O2 `python2.5-config --includes` `python2.5-config --libs` -Wall uwsgi.c
gcc -o uwsgi24 -O2 `python2.4-config --includes` `python2.4-config --libs` -Wall uwsgi.c
gcc -o uwsgi26 -O2 `python2.6-config --includes` `python2.6-config --libs` -Wall uwsgi.c
Compile on *BSD (FreeBSD and OSX)
gcc -o uwsgi -O2 `python2.5-config --includes` `python2.5-config --libs` -Wall -DBSD uwsgi.c


********* Note for OSX/BSD *********
the sockaddr_un structure is defined as
struct sockaddr_un {
        unsigned char  sun_len;
        sa_family_t    sun_family;
        char           sun_path[104];
};

to get the size of addr:
        s_addr.sun_path-s_addr

the sendfile() prototype on BSD is different
************************************

********* Note for Linux users *********
uWSGI supports UNIX socket on abstract namespace.
Use them if you have filesystem permission problems.

********* Note for Unbit users *********
Try to keep the same configuration on your unbit account (threading mode
in particular)

*/
#include <poll.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef BSD
        #include <sys/sendfile.h>
#endif

#include <Python.h>

int init_uwsgi_interpreter(char *mountpoint, char *module, char *callable, char *wsgi_script, int interpreter) ;


char *nl = "\r\n";
#define NL_SIZE 2
char *h_sep = ": " ;
#define H_SEP_SIZE 2

#define PAGE_SIZE 4096

int requests = 0 ;
int has_threads = 0 ;
int wsgi_cnt = 1;
int default_interpreter = -1 ;

struct timeval start_of_uwsgi ;

int cgi_mode = 0 ;
int abstract_socket = 0 ;
int chmod_socket = 0 ;

PyObject *py_sendfile ;

struct pollfd wsgi_poll; 

PyThreadState *wsgi_thread ;

int harakiri_timeout = 60 ;

PyObject *wsgi_writeout ;

#define VEC_SIZE 64

void log_request() ;
void get_memusage() ;

struct __attribute__((packed)) wsgi_request {
        unsigned char version;
        unsigned short size ;
        // temporary attr
        unsigned char interpreter ;     
        struct timeval start_of_request ;
        char *uri;
        unsigned short uri_len;
        char *remote_addr;
        unsigned short remote_addr_len;
        char *remote_user;
        unsigned short remote_user_len;
        char *query_string;
        unsigned short query_string_len;
        char *protocol;
        unsigned short protocol_len;
        char *method;
        unsigned short method_len;
        char *wsgi_script;
        unsigned short wsgi_script_len;
        char *wsgi_module;
        unsigned short wsgi_module_len;
        char *wsgi_callable;
        unsigned short wsgi_callable_len;
        char *script_name;
        unsigned short script_name_len;
        int sendfile_fd;
        unsigned short var_cnt;
        unsigned short header_cnt;
        int status;
        int response_size;
        int headers_size;
        // memory debug
        unsigned long vsz_size;
        long rss_size;
        // iovec
        struct iovec hvec[4+1+4*VEC_SIZE] ;
} wsgi_req;


void harakiri() {
        PyThreadState *_myself ;        
        _myself =  PyThreadState_Get();
        fprintf(stderr,"\nF*CK !!! i must kill myself %p %p...\n", _myself, _myself->frame);
        Py_FatalError("HARAKIRI !\n");
}

void internal_server_error(int fd, char *message) {
        if (cgi_mode == 0) {
                wsgi_req.headers_size = write(fd, "HTTP/1.1 500 Internal Server Error\r\n\r\n", 38);
        }
        else {
                wsgi_req.headers_size = write(fd, "Status: 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 62);
        }
        wsgi_req.response_size = write(fd, "<h1>uWSGI Error</h1>", 20);
        wsgi_req.response_size += write(fd, message, strlen(message));
}

PyObject *py_uwsgi_sendfile(PyObject *self, PyObject *args) {

        PyObject *zero ;

        py_sendfile = PyTuple_GetItem(args, 0);

        if (PyFile_Check(py_sendfile)) {
                zero = PyFile_Name(py_sendfile) ;
                //fprintf(stderr,"->serving %s as static file...", PyString_AsString(zero));
                wsgi_req.sendfile_fd = PyObject_AsFileDescriptor(py_sendfile);
                Py_INCREF(py_sendfile);
        }


        return PyTuple_New(0);
}

PyObject *py_uwsgi_write(PyObject *self, PyObject *args) {
        PyObject *data;
        char *content ;
        int len;
        data = PyTuple_GetItem(args, 0);
        if (PyString_Check(data)) {
                content = PyString_AsString(data) ;
                len = PyString_Size(data);
                if (has_threads) {
                        Py_BEGIN_ALLOW_THREADS
                        wsgi_req.response_size = write(wsgi_poll.fd, content, len);
                        Py_END_ALLOW_THREADS
                }
                else {
                        wsgi_req.response_size = write(wsgi_poll.fd, content, len);
                }
        }
        Py_INCREF(Py_None);
        return Py_None;
}


PyObject *wsgi_spitout;

PyObject *py_uwsgi_spit(PyObject *self, PyObject *args) {
        PyObject *headers, *head ;
        PyObject *h_key, *h_value;
        int i,j ;
        int base = 0 ;

        // use writev()

        // drop http status on cgi mode
        if (cgi_mode == 0) {
                base = 4 ;
                head = PyTuple_GetItem(args,0) ;

                wsgi_req.hvec[0].iov_base = wsgi_req.protocol ;
                wsgi_req.hvec[0].iov_len = wsgi_req.protocol_len ;
                wsgi_req.hvec[1].iov_base = " " ;
                wsgi_req.hvec[1].iov_len = 1 ;
                wsgi_req.hvec[2].iov_base = PyString_AsString(head) ;
                wsgi_req.hvec[2].iov_len = PyString_Size(head) ;
                wsgi_req.status = atoi(wsgi_req.hvec[2].iov_base) ;
                wsgi_req.hvec[3].iov_base = nl ;
                wsgi_req.hvec[3].iov_len = NL_SIZE ;
        }
        
        headers = PyTuple_GetItem(args,1) ;
        wsgi_req.header_cnt = PyList_Size(headers) ;

        if (wsgi_req.header_cnt > VEC_SIZE) {
                wsgi_req.header_cnt = VEC_SIZE ;
        }
        for(i=0;i<wsgi_req.header_cnt;i++) {
                j = (i*4)+base ;
                head = PyList_GetItem(headers, i);
                h_key = PyTuple_GetItem(head,0) ;
                h_value = PyTuple_GetItem(head,1) ;
                wsgi_req.hvec[j].iov_base = PyString_AsString(h_key) ;
                wsgi_req.hvec[j].iov_len = PyString_Size(h_key) ;
                wsgi_req.hvec[j+1].iov_base = h_sep;
                wsgi_req.hvec[j+1].iov_len = H_SEP_SIZE;
                wsgi_req.hvec[j+2].iov_base = PyString_AsString(h_value) ;
                wsgi_req.hvec[j+2].iov_len = PyString_Size(h_value) ;
                wsgi_req.hvec[j+3].iov_base = nl;
                wsgi_req.hvec[j+3].iov_len = NL_SIZE;
        }

        // \r\n
        j = (i*4)+base ;
        wsgi_req.hvec[j].iov_base = nl;
        wsgi_req.hvec[j].iov_len = NL_SIZE;

        wsgi_req.headers_size = writev(wsgi_poll.fd, wsgi_req.hvec,j+1);
        Py_INCREF(wsgi_writeout);
        return wsgi_writeout ;
}


PyMethodDef uwsgi_spit_method[] = {{"uwsgi_spit", py_uwsgi_spit, METH_VARARGS, ""}} ;
PyMethodDef uwsgi_write_method[] = {{"uwsgi_write", py_uwsgi_write, METH_VARARGS, ""}} ;
PyMethodDef uwsgi_sendfile_method[] = {{"uwsgi_sendfile", py_uwsgi_sendfile, METH_VARARGS, ""}} ;

struct uwsgi_interpreter {
        PyThreadState *interpreter ;
        PyObject *wsgi_callable ;
        PyObject *wsgi_environ ;
        PyObject *wsgi_args;
        PyObject *wsgi_sendfile;
        int requests ;
};

struct uwsgi_interpreter wsgi_interpreters[64] ;
PyObject *py_interpreters ;

// save my pid for logging
pid_t mypid;
// flag for memory debug
int memory_debug = 0 ;

int main(int argc, char *argv[]) {

        PyObject *wsgi_result, *wsgi_chunks, *wchunk;
        PyObject *zero, *wsgi_socket;
        PyThreadState *_save = NULL;

        FILE *wsgi_file;
        struct sockaddr_un c_addr ;
        int c_len = sizeof(struct sockaddr_un);
        int rlen,i ;
        pid_t pid ;
        int interpreter = -1 ;
        
        int serverfd = 0 ;
        char *socket_name = NULL ;
        struct sockaddr_un *s_addr;

        PyObject *pydictkey, *pydictvalue;

        char buffer[4096] ;
        char *ptrbuf ;
        char *bufferend ;

        unsigned short strsize;
        struct uwsgi_interpreter *wi;

        int numproc = 1;


        gettimeofday(&start_of_uwsgi, NULL) ;
        fprintf(stderr,"*** Starting uWSGI on [%.*s] ***\n", 24, ctime(&start_of_uwsgi.tv_sec));

        while ((i = getopt (argc, argv, "s:p:t:mcaCT")) != -1) {
                switch(i) {
                        case 's':
                                socket_name = optarg;
                                // leave 1 byte for abstract namespace (108 linux -> 104 bsd/mac)
                                if (strlen(socket_name) > 102) {
                                        fprintf(stderr, "invalid socket name\n");
                                        exit(1);
                                }
                                break;
                        case 'p':
                                numproc = atoi(optarg);
                                break;
                        case 'm':
                                memory_debug = 1 ;
                                break;
                        case 't':
                                harakiri_timeout = atoi(optarg);
                                break;
                        case 'c':
                                fprintf(stderr, "setting cgi mode\n");
                                cgi_mode = 1;
                                break;
                        case 'a':
                                fprintf(stderr, "setting abstract socket mode (warning: only Linux supports this)\n");
                                abstract_socket = 1;
                                break;
                        case 'T':
                                has_threads = 1;
                                break;
                        case 'C':
                                chmod_socket = 1;
                                break;
                }
        }

        Py_SetProgramName("uWSGI");
        Py_Initialize() ;

        wsgi_thread = PyThreadState_Get();


        if (has_threads) {
                PyEval_InitThreads() ;
                fprintf(stderr, "threads support enabled\n");
        }

        if (socket_name != NULL) {
                fprintf(stderr, "binding on UNIX socket: %s\n", socket_name);
                s_addr = malloc(sizeof(struct sockaddr_un));
                if (s_addr == NULL) {
                        perror("malloc()");
                        exit(1);
                }
                memset(s_addr, 0, sizeof(struct sockaddr_un)) ;
                serverfd = socket(AF_UNIX, SOCK_STREAM, 0);
                if (serverfd < 0) {
                        perror("socket()");
                        exit(1);
                }
                if (abstract_socket == 0) {
                        if (unlink(socket_name) != 0) {
                                perror("unlink()");
                        }
                }
                s_addr->sun_family = AF_UNIX;
                strcpy(s_addr->sun_path+abstract_socket, socket_name);
                
                if (bind(serverfd, (struct sockaddr *) s_addr, strlen(socket_name)+ abstract_socket + ( (void *)s_addr->sun_path - (void *)s_addr) ) != 0) {
                        perror("bind()");
                        exit(1);
                }

                if (listen(serverfd, 64) != 0) {
                        perror("listen()");
                        exit(1);
                }

                // chmod unix socket for lazy users
                if (chmod_socket == 1 && abstract_socket == 0) {
                        fprintf(stderr, "chmod() socket to 666 for lazy and brave users\n");
                        if (chmod(socket_name, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) != 0) {
                                perror("chmod()");
                        }
                }
                
        }

        py_interpreters = PyDict_New();
        if (!py_interpreters) {
                PyErr_Print();
                exit(1);
        }

        wsgi_spitout = PyCFunction_New(uwsgi_spit_method,NULL) ;
        wsgi_writeout = PyCFunction_New(uwsgi_write_method,NULL) ;

        memset(wsgi_interpreters, 0, sizeof(wsgi_interpreters));


        if (has_threads) {
                _save = PyEval_SaveThread();
        }

        if (harakiri_timeout > 0) {
                signal(SIGALRM, harakiri);
        }

        signal(SIGINT, harakiri);

        wsgi_poll.events = POLLIN ;

        memset(&wsgi_req, 0, sizeof(struct wsgi_request));
        wsgi_req.sendfile_fd = -1 ;

        mypid = getpid();

        /* preforking() */
        fprintf(stderr, "spawned uWSGI worker 0 (pid: %d)\n", mypid);
        for(i=1;i<numproc;i++) {
                pid = fork();
                if (pid == 0 ) {
                        mypid = getpid();
                        break;
                }
                else if (pid < 1) {
                        perror("fork()");
                        exit(1);
                }
                else {
                        fprintf(stderr, "Spawned uWSGI worker %d (pid: %d)\n", i, pid);
                }
        }

        while( (wsgi_poll.fd = accept(serverfd,(struct sockaddr *)&c_addr, (socklen_t *) &c_len)) ) {

                if (wsgi_poll.fd < 0){
                        perror("accept()");
                        exit(1);
                }

                /*
                        poll con timeout ;
                */

                gettimeofday(&wsgi_req.start_of_request, NULL) ;

                /* first 4 byte header */
                rlen = poll(&wsgi_poll, 1, 4000) ;
                if (rlen < 0) {
                        perror("poll()");
                        exit(1);
                }
                else if (rlen == 0) {
                        fprintf(stderr, "timeout. skip request\n");
                        close(wsgi_poll.fd);
                        continue ;      
                }
                rlen = read(wsgi_poll.fd, &wsgi_req, 4) ;
                if (rlen != 4){
                        fprintf(stderr,"invalid request header size: %d...skip\n", rlen);
                        continue;
                }
                if (wsgi_req.size > 4096) {
                        fprintf(stderr,"invalid request block size: %d...skip\n", wsgi_req.size);
                        continue;
                }

                /* http headers parser */
                rlen = poll(&wsgi_poll, 1, 4000) ;
                if (rlen < 0) {
                        perror("poll()");
                        exit(1);
                }
                else if (rlen == 0) {
                        fprintf(stderr, "timeout. skip request\n");
                        close(wsgi_poll.fd);
                        continue ;
                }
                rlen = read(wsgi_poll.fd, buffer, wsgi_req.size);
                if (rlen != wsgi_req.size){
                        fprintf(stderr,"invalid request var size: %d...skip\n", rlen);
                        continue;
                }


                ptrbuf = buffer ;
                bufferend = ptrbuf+wsgi_req.size ;


                        // pluginIZE this part (ucgi, fastcgi, scgi, http...)
                        while(ptrbuf < bufferend) {
                                if (ptrbuf+2 < bufferend) {
                                        memcpy(&strsize,ptrbuf,2);
                                        ptrbuf+=2;
                                        if (ptrbuf+strsize < bufferend) {
                                                // var key
                                                wsgi_req.hvec[wsgi_req.var_cnt].iov_base = ptrbuf ;
                                                wsgi_req.hvec[wsgi_req.var_cnt].iov_len = strsize ;
                                                ptrbuf+=strsize;
                                                if (ptrbuf+2 < bufferend) {
                                                        memcpy(&strsize,ptrbuf,2);
                                                        ptrbuf+=2 ;
                                                        if ( ptrbuf+strsize <= bufferend) {
                                                                if (!strncmp("SCRIPT_NAME", wsgi_req.hvec[wsgi_req.var_cnt].iov_base , wsgi_req.hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        // set the subinterpreter
                                                                        // LOCKED SECTION
                                                                        if (strsize > 0) {
                                                                                if (has_threads) {
                                                                                        PyEval_RestoreThread(_save);
                                                                                }
                                                                                zero = PyString_FromStringAndSize(ptrbuf, strsize) ;
                                                                                if (PyDict_Contains(py_interpreters, zero)) {
                                                                                        interpreter = PyInt_AsLong( PyDict_GetItem(py_interpreters, zero) );
                                                                                }
                                                                                else {
                                                                                        /* unavailable interpreter for this SCRIPT_NAME */
                                                                                        interpreter = -1 ;
                                                                                }
                                                                                Py_DECREF(zero);
                                                                                if (has_threads) {
                                                                                        _save = PyEval_SaveThread();
                                                                                }
                                                                        }
                                                                        // UNLOCK
                                                                }
                                                                else if (!strncmp("SERVER_PROTOCOL", wsgi_req.hvec[wsgi_req.var_cnt].iov_base , wsgi_req.hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.protocol = ptrbuf ;
                                                                        wsgi_req.protocol_len = strsize ;
                                                                }
                                                                else if (!strncmp("REQUEST_URI", wsgi_req.hvec[wsgi_req.var_cnt].iov_base, wsgi_req.hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.uri = ptrbuf ;
                                                                        wsgi_req.uri_len = strsize ;
                                                                }
                                                                else if (!strncmp("QUERY_STRING", wsgi_req.hvec[wsgi_req.var_cnt].iov_base, wsgi_req.hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.query_string = ptrbuf ;
                                                                        wsgi_req.query_string_len = strsize ;
                                                                }
                                                                else if (!strncmp("REQUEST_METHOD", wsgi_req.hvec[wsgi_req.var_cnt].iov_base, wsgi_req.hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.method = ptrbuf ;
                                                                        wsgi_req.method_len = strsize ;
                                                                }
                                                                else if (!strncmp("REMOTE_ADDR", wsgi_req.hvec[wsgi_req.var_cnt].iov_base, wsgi_req.hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.remote_addr = ptrbuf ;
                                                                        wsgi_req.remote_addr_len = strsize ;
                                                                }
                                                                else if (!strncmp("REMOTE_USER", wsgi_req.hvec[wsgi_req.var_cnt].iov_base, wsgi_req.hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.remote_user = ptrbuf ;
                                                                        wsgi_req.remote_user_len = strsize ;
                                                                }
                                                                wsgi_req.var_cnt++ ;
                                                                // var value
                                                                wsgi_req.hvec[wsgi_req.var_cnt].iov_base = ptrbuf ;
                                                                wsgi_req.hvec[wsgi_req.var_cnt].iov_len = strsize ;
                                                                wsgi_req.var_cnt++ ;
                                                                ptrbuf+=strsize;
                                                        }
                                                        else {
                                                                break;
                                                        }
                                                }
                                                else {
                                                        break;
                                                }
                                        }
                                }
                                else {
                                        break;
                                }
                        }

                if (has_threads) {
                        PyEval_RestoreThread(_save);
                }

                wsgi_file = fdopen(wsgi_poll.fd,"r") ;

                if (interpreter == -1) {
                        for(i=0;i<wsgi_req.var_cnt;i+=2) {
                                if (!strncmp("SCRIPT_NAME", wsgi_req.hvec[i].iov_base, wsgi_req.hvec[i].iov_len)) {
                                        wsgi_req.script_name = wsgi_req.hvec[i+1].iov_base ;
                                        wsgi_req.script_name_len = wsgi_req.hvec[i+1].iov_len ;
                                }
                                if (!strncmp("UWSGI_SCRIPT", wsgi_req.hvec[i].iov_base, wsgi_req.hvec[i].iov_len)) {
                                        wsgi_req.wsgi_script = wsgi_req.hvec[i+1].iov_base ;
                                        wsgi_req.wsgi_script_len = wsgi_req.hvec[i+1].iov_len ;
                                }
                                if (!strncmp("UWSGI_MODULE", wsgi_req.hvec[i].iov_base, wsgi_req.hvec[i].iov_len)) {
                                        wsgi_req.wsgi_module = wsgi_req.hvec[i+1].iov_base ;
                                        wsgi_req.wsgi_module_len = wsgi_req.hvec[i+1].iov_len ;
                                }
                                if (!strncmp("UWSGI_CALLABLE", wsgi_req.hvec[i].iov_base, wsgi_req.hvec[i].iov_len)) {
                                        wsgi_req.wsgi_callable = wsgi_req.hvec[i+1].iov_base ;
                                        wsgi_req.wsgi_callable_len = wsgi_req.hvec[i+1].iov_len ;
                                }
                        }


                        if (wsgi_req.wsgi_script_len > 0) {
                                if (wsgi_req.script_name_len > 0) {
                                        if (init_uwsgi_interpreter(wsgi_req.script_name, NULL, NULL, wsgi_req.wsgi_script, wsgi_cnt)) {
                                                interpreter = wsgi_cnt-1 ;
                                        }
                                }
                                else {

                                        if (init_uwsgi_interpreter("/", NULL, NULL, wsgi_req.wsgi_script, 0)) {
                                                interpreter = 0 ;
                                        }
                                }
                        }
                        else if (wsgi_req.wsgi_module_len > 0 && wsgi_req.wsgi_callable_len > 0) {
                                if (wsgi_req.script_name_len > 0) {
                                        if (init_uwsgi_interpreter(wsgi_req.script_name, wsgi_req.wsgi_module, wsgi_req.wsgi_callable, NULL, wsgi_cnt)) {
                                                interpreter = wsgi_cnt-1 ;
                                        }
                                }
                                else {
                                        if (init_uwsgi_interpreter("/", wsgi_req.wsgi_module, wsgi_req.wsgi_callable, NULL, 0)) {
                                                interpreter = 0 ;
                                        }
                                }
                        }
                        else {
                                internal_server_error(wsgi_poll.fd, "wsgi application not found");
                                goto clean ;
                        }
                }

                if (interpreter == -1) {
                        internal_server_error(wsgi_poll.fd, "wsgi application not found");
                        goto clean;
                }

                wi = &wsgi_interpreters[interpreter] ;

                if (!wi->interpreter) {
                        internal_server_error(wsgi_poll.fd, "wsgi application not found");
                        goto clean;
                }

                // set the interpreter
                PyThreadState_Swap(wi->interpreter) ;

                /* max 1 minute before harakiri */
                if (harakiri_timeout > 0) {
                        alarm(harakiri_timeout);
                }

                for(i=0;i<wsgi_req.var_cnt;i+=2) {
                        pydictkey = PyString_FromStringAndSize(wsgi_req.hvec[i].iov_base, wsgi_req.hvec[i].iov_len) ;
                        pydictvalue = PyString_FromStringAndSize(wsgi_req.hvec[i+1].iov_base, wsgi_req.hvec[i+1].iov_len) ;
                        PyDict_SetItem(wi->wsgi_environ, pydictkey, pydictvalue);
                        Py_DECREF(pydictkey);
                        Py_DECREF(pydictvalue);
                }

                // set wsgi vars

                wsgi_socket = PyFile_FromFile(wsgi_file,"wsgi_input","r", NULL) ;
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.input", wsgi_socket );
                Py_DECREF(wsgi_socket) ;

                PyDict_SetItemString(wi->wsgi_environ, "wsgi.file_wrapper", wi->wsgi_sendfile );

                zero = PyTuple_New(2);
                PyTuple_SetItem(zero, 0 , PyInt_FromLong(1));
                PyTuple_SetItem(zero, 1 , PyInt_FromLong(0));
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.version", zero);
                Py_DECREF(zero);

                zero = PyFile_FromFile(stderr, "wsgi_input","w", NULL) ;
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.errors", zero );
                Py_DECREF(zero) ;

                PyDict_SetItemString(wi->wsgi_environ, "wsgi.run_once", Py_False);

                PyDict_SetItemString(wi->wsgi_environ, "wsgi.multithread", Py_False);
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.multiprocess", Py_True);

                zero = PyString_FromString("http") ;
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.url_scheme", zero);
                Py_DECREF(zero);


                // call
                wsgi_result = PyEval_CallObject(wi->wsgi_callable, wi->wsgi_args);

                if (PyErr_Occurred()) {
                        PyErr_Print();
                }

                if (wsgi_result) {
                        if (wsgi_req.sendfile_fd > -1) {
                                rlen = lseek(wsgi_req.sendfile_fd, 0, SEEK_END) ;
                                if (rlen > 0) {
                                        lseek(wsgi_req.sendfile_fd, 0, SEEK_SET) ;
#ifdef BSD
                                        wsgi_req.response_size = sendfile(wsgi_req.sendfile_fd, wsgi_poll.fd, 0, (off_t *) &rlen, NULL, 0) ;
#else
                                        wsgi_req.response_size = sendfile(wsgi_poll.fd, wsgi_req.sendfile_fd, NULL, rlen) ;
#endif
                                }
                                Py_DECREF(py_sendfile);
                        }
                        else {
                                wsgi_chunks = PyObject_GetIter(wsgi_result);
                                if (wsgi_chunks) {
                                        while((wchunk = PyIter_Next(wsgi_chunks))) {
                                                if (PyString_Check(wchunk)) {
                                                        wsgi_req.response_size += write(wsgi_poll.fd, PyString_AsString(wchunk), PyString_Size(wchunk)) ;
                                                }
                                                Py_DECREF(wchunk);
                                        }
                                        Py_DECREF(wsgi_chunks);
                                }
                        }
                        Py_DECREF(wsgi_result);
                }


                PyDict_Clear(wi->wsgi_environ);
                wi->requests++;
                PyErr_Clear();
                if (harakiri_timeout > 0) {
                        alarm(0);
                }
                PyThreadState_Swap(wsgi_thread);
clean:
                fclose(wsgi_file);
                /* default interpreter */
                if (has_threads) {
                        _save = PyEval_SaveThread();
                }
                requests++ ;
                // GO LOGGING...
                log_request() ;
                // reset to default interpreter
                interpreter = default_interpreter ;
                memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
                wsgi_req.sendfile_fd = -1 ;

        }

        return 0 ;

}

void log_request() {
        char *time_request ;
        struct timeval end_request ;
        time_t microseconds, microseconds2;

        char *msg1 = " via sendfile() " ;
        char *msg2 = " " ;
        char *msg3 = "?" ;
        char *msg4 = "" ;

        char *via ;
        char *qs_sep;

        via = msg2 ;
        if (wsgi_req.sendfile_fd > -1) {
                via = msg1 ;
        }

        qs_sep = msg4 ;
        if (wsgi_req.query_string_len > 0) {
                qs_sep = msg3 ;
        }
        
        time_request = ctime(&wsgi_req.start_of_request.tv_sec);
        gettimeofday(&end_request, NULL) ;
        microseconds = end_request.tv_sec*1000000+end_request.tv_usec ;
        microseconds2 = wsgi_req.start_of_request.tv_sec*1000000+wsgi_req.start_of_request.tv_usec ;
        if (memory_debug == 1) {
                get_memusage();
                fprintf(stderr,"{address space usage: %ld bytes/%luMB} {rss usage: %lu bytes/%luMB} ", wsgi_req.vsz_size, wsgi_req.vsz_size/1024/1024, wsgi_req.rss_size*PAGE_SIZE, (wsgi_req.rss_size*PAGE_SIZE)/1024/1024) ;
        }
        fprintf(stderr, "[%d/%d] %.*s (%.*s) {%d vars in %d bytes} [%.*s] %.*s %.*s%s%.*s => generated %d bytes in %ld msecs%s(%.*s %d) %d headers in %d bytes\n",
                mypid, requests, wsgi_req.remote_addr_len, wsgi_req.remote_addr,
                wsgi_req.remote_user_len, wsgi_req.remote_user, wsgi_req.var_cnt, wsgi_req.size, 24, time_request,
                wsgi_req.method_len, wsgi_req.method, wsgi_req.uri_len, wsgi_req.uri, qs_sep, wsgi_req.query_string_len, wsgi_req.query_string, wsgi_req.response_size, 
                (microseconds-microseconds2)/1000, via,
                wsgi_req.protocol_len, wsgi_req.protocol, wsgi_req.status, wsgi_req.header_cnt, wsgi_req.headers_size) ;

}

void get_memusage() {
        FILE *procfile;
        int i;

        procfile = fopen("/proc/self/stat","r");
        if (procfile) {
                i = fscanf(procfile,"%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %ld",&wsgi_req.vsz_size, &wsgi_req.rss_size) ;
                if (i != 2) {
                        fprintf(stderr, "warning: invalid record in /proc/self/stat\n");
                }
                fclose(procfile);
        }
}

int init_uwsgi_interpreter(char *mountpoint, char *module, char *callable, char *wsgi_script, int interpreter) {
        PyObject *wsgi_module, *wsgi_dict, *wsgi_argv, *zero ;
        PyObject *pysys, *pysys_dict, *pypath;
        char tmpstring[256] ;

        struct uwsgi_interpreter *wi ;

        memset(tmpstring,0, 256) ;

        wi = &wsgi_interpreters[interpreter] ;

        wi->interpreter = Py_NewInterpreter();


        PyThreadState_Swap(wi->interpreter) ;

        /* stolen from mod_wsgi, sorry ;) */
        wsgi_argv = PyList_New(0);
        zero = PyString_FromString("uwsgi");
        PyList_Append(wsgi_argv, zero);
        PySys_SetObject("argv", wsgi_argv);
        Py_DECREF(zero);
        Py_DECREF(wsgi_argv);


        /* add cwd and cvalue to pythonpath */
        pysys = PyImport_ImportModule("sys");
        if (!pysys) {
                PyErr_Print();
                exit(1);
        }
        pysys_dict = PyModule_GetDict(pysys);
        pypath = PyDict_GetItemString(pysys_dict, "path");
        if (!pypath) {
                PyErr_Print();
                exit(1);
        }
        PyList_Insert(pypath,0,PyString_FromString("."));


        if (wsgi_script) {
                memcpy(tmpstring, wsgi_script, wsgi_req.wsgi_script_len) ;
                wsgi_module = PyImport_ImportModule(tmpstring) ;
                if (!wsgi_module) {
                        PyErr_Print();
                        Py_EndInterpreter(wi->interpreter);
                        PyThreadState_Swap(wsgi_thread) ;
                        return 0 ;
                }
                callable = "application" ;
                wsgi_req.wsgi_callable_len = 11;
        }
        else {
                memcpy(tmpstring, module, wsgi_req.wsgi_module_len) ;
                wsgi_module = PyImport_ImportModule(tmpstring) ;
                if (!wsgi_module) {
                        PyErr_Print();
                        Py_EndInterpreter(wi->interpreter);
                        PyThreadState_Swap(wsgi_thread) ;
                        return 0 ;
                }
                
        }

        wsgi_dict = PyModule_GetDict(wsgi_module);
        if (!wsgi_dict) {
                PyErr_Print();
                Py_EndInterpreter(wi->interpreter);
                PyThreadState_Swap(wsgi_thread) ;
                return 0 ;
        }

        memset(tmpstring, 0, 256);
        memcpy(tmpstring, callable, wsgi_req.wsgi_callable_len) ;
        wi->wsgi_callable = PyDict_GetItemString(wsgi_dict, tmpstring);
        if (!wi->wsgi_callable) {
                PyErr_Print();
                Py_EndInterpreter(wi->interpreter);
                PyThreadState_Swap(wsgi_thread) ;
                return 0 ;
        }


        wi->wsgi_environ = PyDict_New();
        if (!wi->wsgi_environ) {
                PyErr_Print();
                Py_EndInterpreter(wi->interpreter);
                PyThreadState_Swap(wsgi_thread) ;
                return 0 ;
        }

        wi->wsgi_args = PyTuple_New(2) ;
        if (PyTuple_SetItem(wi->wsgi_args,0, wi->wsgi_environ)) {
                PyErr_Print();
                Py_EndInterpreter(wi->interpreter);
                PyThreadState_Swap(wsgi_thread) ;
                return 0 ;
        }
        if (PyTuple_SetItem(wi->wsgi_args,1, wsgi_spitout)) {
                PyErr_Print();
                Py_EndInterpreter(wi->interpreter);
                PyThreadState_Swap(wsgi_thread) ;
                return 0 ;
        }

        wi->wsgi_sendfile = PyCFunction_New(uwsgi_sendfile_method,NULL) ;

        PyThreadState_Swap(wsgi_thread);
        memset(tmpstring, 0, 256);
        if (wsgi_req.script_name_len > 0) {
                memcpy(tmpstring, mountpoint, wsgi_req.script_name_len);
        }
        else {
                memcpy(tmpstring, mountpoint, 1);
        }
        PyDict_SetItemString(py_interpreters, tmpstring, PyInt_FromLong(interpreter));
        PyErr_Print();

        fprintf(stderr,"interpreter %d (%s) ready\n", interpreter, tmpstring);

        if (interpreter == 0){
                fprintf(stderr,"setting default interpreter to 0\n");
                default_interpreter = 0 ;
        }

        wsgi_cnt++;

        return 1 ;
}





