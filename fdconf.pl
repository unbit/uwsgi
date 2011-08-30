use POSIX;

open CONFIG,'welcome.ini';

dup2(fileno(CONFIG), 17);

exec './uwsgi','--ini','fd://17';
