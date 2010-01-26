#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void log_request(struct wsgi_request *wsgi_req) {
        char *time_request ;
        struct timeval end_request ;
        time_t microseconds, microseconds2;


#ifndef ROCK_SOLID
        char *msg1 = " via sendfile() " ;
        char *msg2 = " " ;
        char *via ;
	#ifndef ROCK_SOLID
	static char *empty = "";
	#endif

        char *first_part = empty ;
        struct uwsgi_app *wi;
        int app_req = -1 ;

        if (wsgi_req->app_id >= 0) {
                wi = &uwsgi.wsgi_apps[wsgi_req->app_id] ;
                if (wi->requests > 0) {
                        app_req = wi->requests ;
                }
        }
        via = msg2 ;
        if (wsgi_req->sendfile_fd > -1) {
                via = msg1 ;
        }
#endif

        time_request = ctime( (const time_t *) &wsgi_req->start_of_request.tv_sec);
        gettimeofday(&end_request, NULL) ;
        microseconds = end_request.tv_sec*1000000+end_request.tv_usec ;
        microseconds2 = wsgi_req->start_of_request.tv_sec*1000000+wsgi_req->start_of_request.tv_usec ;


#ifndef ROCK_SOLID
        if (uwsgi.options[UWSGI_OPTION_MEMORY_DEBUG] == 1) {
                get_memusage();
#ifndef UNBIT
                if (uwsgi.synclog) {
                        snprintf(uwsgi.sync_page, uwsgi.page_size, "{address space usage: %lld bytes/%lluMB} {rss usage: %llu bytes/%lluMB} ", uwsgi.workers[uwsgi.mywid].vsz_size, uwsgi.workers[uwsgi.mywid].vsz_size/1024/1024, uwsgi.workers[uwsgi.mywid].rss_size, uwsgi.workers[uwsgi.mywid].rss_size/1024/1024) ;
                        first_part = uwsgi.sync_page;
                }
                else {
                        fprintf(stderr,"{address space usage: %lld bytes/%lluMB} {rss usage: %llu bytes/%lluMB} ", uwsgi.workers[uwsgi.mywid].vsz_size, uwsgi.workers[uwsgi.mywid].vsz_size/1024/1024, uwsgi.workers[uwsgi.mywid].rss_size, uwsgi.workers[uwsgi.mywid].rss_size/1024/1024) ;
                }
#else
                fprintf(stderr,"{address space usage: %lld bytes/%lluMB} ", uwsgi.workers[uwsgi.mywid].vsz_size, uwsgi.workers[uwsgi.mywid].vsz_size/1024/1024) ;
#endif
        }
#endif

        uwsgi.workers[uwsgi.mywid].running_time += (double) (( (double)microseconds-(double)microseconds2)/ (double)1000.0) ;

#ifdef ROCK_SOLID
        fprintf(stderr, "[pid: %d|req: %llu] %.*s (%.*s) {%d vars in %d bytes} [%.*s] %.*s %.*s => generated %d bytes in %ld msecs (%.*s %d) %d headers in %d bytes\n",
                uwsgi.mypid, uwsgi.workers[0].requests, wsgi_req->remote_addr_len, wsgi_req->remote_addr,
                wsgi_req->remote_user_len, wsgi_req->remote_user, wsgi_req->var_cnt, wsgi_req->size, 24, time_request,
                wsgi_req->method_len, wsgi_req->method, wsgi_req->uri_len, wsgi_req->uri, wsgi_req->response_size,
                (microseconds-microseconds2)/1000,
                wsgi_req->protocol_len, wsgi_req->protocol, wsgi_req->status, wsgi_req->header_cnt, wsgi_req->headers_size) ;
#else
        fprintf(stderr, "%s[pid: %d|app: %d|req: %d/%llu] %.*s (%.*s) {%d vars in %d bytes} [%.*s] %.*s %.*s => generated %d bytes in %ld msecs%s(%.*s %d) %d headers in %d bytes\n", first_part,
                uwsgi.mypid, wsgi_req->app_id, app_req, uwsgi.workers[0].requests, wsgi_req->remote_addr_len, wsgi_req->remote_addr,
                wsgi_req->remote_user_len, wsgi_req->remote_user, wsgi_req->var_cnt, wsgi_req->size, 24, time_request,
                wsgi_req->method_len, wsgi_req->method, wsgi_req->uri_len, wsgi_req->uri, wsgi_req->response_size,
                (microseconds-microseconds2)/1000, via,
                wsgi_req->protocol_len, wsgi_req->protocol, wsgi_req->status, wsgi_req->header_cnt, wsgi_req->headers_size) ;
#endif


}

#ifndef ROCK_SOLID
void get_memusage() {

#ifdef UNBIT
        uwsgi.workers[uwsgi.mywid].vsz_size = syscall(356);
#else
#ifdef __linux__
        FILE *procfile;
        int i;
        procfile = fopen("/proc/self/stat","r");
        if (procfile) {
                i = fscanf(procfile,"%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu %lld",&uwsgi.workers[uwsgi.mywid].vsz_size, &uwsgi.workers[uwsgi.mywid].rss_size) ;
                if (i != 2) {
                        fprintf(stderr, "warning: invalid record in /proc/self/stat\n");
                }
                fclose(procfile);
        }
        uwsgi.workers[uwsgi.mywid].rss_size = uwsgi.workers[uwsgi.mywid].rss_size*uwsgi.page_size;
#endif
#ifdef __APPLE__
        /* darwin documentation says that the value are in pages, bot they are bytes !!! */
        struct task_basic_info t_info;
        mach_msg_type_number_t t_size = sizeof(struct task_basic_info);

        if (task_info(mach_task_self(),TASK_BASIC_INFO, (task_info_t)&t_info, &t_size) == KERN_SUCCESS) {
                uwsgi.workers[uwsgi.mywid].rss_size = t_info.resident_size;
                uwsgi.workers[uwsgi.mywid].vsz_size = t_info.virtual_size;
        }

#endif
#endif
}
#endif

