#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_cron *uwsgi_cron_add(char *crontab) {
	int i;
        struct uwsgi_cron *old_uc, *uc = uwsgi.crons;
        if (!uc) {
                uc = uwsgi_malloc(sizeof(struct uwsgi_cron));
                uwsgi.crons = uc;
        }
        else {
                old_uc = uc;
                while (uc->next) {
                        uc = uc->next;
                        old_uc = uc;
                }

                old_uc->next = uwsgi_malloc(sizeof(struct uwsgi_cron));
                uc = old_uc->next;
        }

        memset(uc, 0, sizeof(struct uwsgi_cron));

        if (sscanf(crontab, "%d %d %d %d %d %n", &uc->minute, &uc->hour, &uc->day, &uc->month, &uc->week, &i) != 5) {
                uwsgi_log("invalid cron syntax\n");
                exit(1);
        }
        uc->command = crontab + i;
        uc->pid = -1;
        return uc;
}


void uwsgi_opt_add_cron(char *opt, char *value, void *foobar) {
        uwsgi_cron_add(value);
}


void uwsgi_opt_add_unique_cron(char *opt, char *value, void *foobar) {
        struct uwsgi_cron *uc = uwsgi_cron_add(value);
        uc->unique = 1;
}


#ifdef UWSGI_SSL
void uwsgi_opt_add_legion_cron(char *opt, char *value, void *foobar) {
        char *space = strchr(value, ' ');
        if (!space) {
                uwsgi_log("invalid %s syntax, must be prefixed with a legion name\n", opt);
                exit(1);
        }
        char *legion = uwsgi_concat2n(value, space-value, "", 0);
        struct uwsgi_cron *uc = uwsgi_cron_add(space+1);
        uc->legion = legion;
}


void uwsgi_opt_add_unique_legion_cron(char *opt, char *value, void *foobar) {
        char *space = strchr(value, ' ');
        if (!space) {
                uwsgi_log("invalid %s syntax, must be prefixed with a legion name\n", opt);
                exit(1);
        }
        char *legion = uwsgi_concat2n(value, space-value, "", 0);
        struct uwsgi_cron *uc = uwsgi_cron_add(space+1);
        uc->legion = legion;
        uc->unique = 1;
}
#endif


int uwsgi_signal_add_cron(uint8_t sig, int minute, int hour, int day, int month, int week) {

        if (!uwsgi.master_process)
                return -1;

        uwsgi_lock(uwsgi.cron_table_lock);

        if (ushared->cron_cnt < MAX_CRONS) {

                ushared->cron[ushared->cron_cnt].sig = sig;
                ushared->cron[ushared->cron_cnt].minute = minute;
                ushared->cron[ushared->cron_cnt].hour = hour;
                ushared->cron[ushared->cron_cnt].day = day;
                ushared->cron[ushared->cron_cnt].month = month;
                ushared->cron[ushared->cron_cnt].week = week;
                ushared->cron_cnt++;
        }
        else {
                uwsgi_log("you can register max %d cron !!!\n", MAX_CRONS);
                uwsgi_unlock(uwsgi.cron_table_lock);
                return -1;
        }

        uwsgi_unlock(uwsgi.cron_table_lock);

        return 0;
}

void uwsgi_manage_signal_cron(time_t now) {

        struct tm *uwsgi_cron_delta;
        int i;

        uwsgi_cron_delta = localtime(&now);

        if (uwsgi_cron_delta) {

                // fix month
                uwsgi_cron_delta->tm_mon++;

                uwsgi_lock(uwsgi.cron_table_lock);
                for (i = 0; i < ushared->cron_cnt; i++) {

                        struct uwsgi_cron *ucron = &ushared->cron[i];

                        int run_task = uwsgi_cron_task_needs_execution(uwsgi_cron_delta, ucron->minute, ucron->hour, ucron->day, ucron->month, ucron->week);

                        if (run_task == 1) {
                                // date match, signal it ?
                                if (now - ucron->last_job >= 60) {
                                        uwsgi_route_signal(ucron->sig);
                                        ucron->last_job = now;
                                }
                        }

                }
                uwsgi_unlock(uwsgi.cron_table_lock);
        }
        else {
                uwsgi_error("localtime()");
        }

}

void uwsgi_manage_command_cron(time_t now) {

        struct tm *uwsgi_cron_delta;

        struct uwsgi_cron *current_cron = uwsgi.crons;

        uwsgi_cron_delta = localtime(&now);


        if (!uwsgi_cron_delta) {
                uwsgi_error("uwsgi_manage_command_cron()/localtime()");
                return;
        }

        // fix month
        uwsgi_cron_delta->tm_mon++;

        while (current_cron) {

#ifdef UWSGI_SSL
                // check for legion cron
                if (current_cron->legion) {
                        if (!uwsgi_legion_i_am_the_lord(current_cron->legion))
                            goto next;
                }
#endif

		// skip unique crons that are still running
		if (current_cron->unique && current_cron->pid >= 0)
			goto next;

                int run_task = uwsgi_cron_task_needs_execution(uwsgi_cron_delta, current_cron->minute, current_cron->hour, current_cron->day, current_cron->month, current_cron->week);
                if (run_task == 1) {

                        // date match, run command ?
                        if (now - current_cron->last_job >= 60) {
                                //call command
                                if (current_cron->command) {
					if (current_cron->func) {
						current_cron->func(current_cron, now);
					}
					else {
						pid_t pid = uwsgi_run_command(current_cron->command, NULL, -1);
						if (pid >= 0) {
							current_cron->pid = pid;
							current_cron->started_at = now;
							uwsgi_log_verbose("[uwsgi-cron] running \"%s\" (pid %d)\n", current_cron->command, current_cron->pid);
							if (uwsgi.cron_harakiri)
								current_cron->harakiri = now + uwsgi.cron_harakiri;
						}
					}
                                }
                                current_cron->last_job = now;
                        }
                }

next:
                current_cron = current_cron->next;
        }
}

