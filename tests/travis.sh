#!/bin/bash
set -u


CI_CONFIG="$1"
txtund=$(tput sgr 0 1)          # underline
txtbld=$(tput bold)             # bold
bldred=${txtbld}$(tput setaf 1) # red
bldgre=${txtbld}$(tput setaf 2) # green
bldyel=${txtbld}$(tput setaf 3) # yellow
bldblu=${txtbld}$(tput setaf 4) # blue
txtcya=$(tput setaf 6)          # cyan
bldwht=${txtbld}$(tput setaf 7) # white
txtrst=$(tput sgr0)             # reset


ERROR=0
SUCCESS=0


die() {
    date > reload.txt
    sleep 3
    pidof uwsgi && killall uwsgi
    sleep 1
    pidof uwsgi && killall -9 uwsgi
    echo -e "$@"
    if [ -e uwsgi.log ]; then
        echo -e "${bldyel}>>> uwsgi.log:${txtrst}"
        echo -e "${txtcya}"
        cat uwsgi.log
        echo -e "${txtrst}"
    fi
}


http_test() {
    URL=$1
    UPID=`pidof uwsgi`
    if [ "$UPID" != "" ]; then
        echo -e "${bldgre}>>> Spawned PID $UPID, running tests${txtrst}"
        sleep 5
        curl -fI $URL
        RET=$?
        if [ $RET != 0 ]; then
            die "${bldred}>>> Error during curl run${txtrst}"
            ERROR=$((ERROR+1))
        elif fgrep '[ERROR]' uwsgi.log > /dev/null ; then
            # Blindly report any [ERROR] string in the log file as failure.
            # This obviously won't work when for tests purposely generating
            # [ERROR] messages.
            die "${bldred}>>> ERROR in uwsgi.log!${txtrst}"
            ERROR=$((ERROR+1))
        else
            die "${bldyel}>>> SUCCESS: Done${txtrst}"
            SUCCESS=$((SUCCESS+1))
        fi

    else
        die "${bldred}>>> ERROR: uWSGI did not start${txtrst}"
        ERROR=$((ERROR+1))
    fi
}


test_python() {
    date > reload.txt
    rm -f uwsgi.log
    echo -e "${bldyel}================== TESTING $1 $2 =====================${txtrst}"
    echo -e "${bldyel}>>> Spawning uWSGI python app${txtrst}"
    echo -en "${bldred}"
    ./uwsgi --master --plugin 0:$1 --http :8080 --exit-on-reload --touch-reload reload.txt --wsgi-file $2 --daemonize uwsgi.log
    sleep 1
    echo -en "${txtrst}"
    http_test "http://localhost:8080/"
    echo -e "${bldyel}===================== DONE $1 $2 =====================${txtrst}\n\n"
}


test_python_deadlocks() {
    date > reload.txt
    rm -f uwsgi.log
    echo -e "${bldyel}================== TESTING DEADLOCKS $1 $2 =====================${txtrst}"
    echo -e "${bldyel}>>> Starting python app${txtrst}"
    echo -en "${bldred}"
    # initialize with tests/deadlocks/sitecustomize.py
    PYTHONPATH=tests/deadlocks ./uwsgi --plugin 0:$1 --http :8080 --exit-on-reload --touch-reload reload.txt --wsgi-file tests/deadlocks/main.py --ini $2 --daemonize uwsgi.log
    sleep 1
    echo -en "${txtrst}"
    http_test "http://localhost:8080/"
    echo -e "${bldyel}===================== DONE $1 $2 =====================${txtrst}\n\n"
}


test_rack() {
    date > reload.txt
    rm -f uwsgi.log
    # the code assumes that ruby environment is activated by `rvm use`
    echo -e "${bldyel}================== TESTING $1 $2 =====================${txtrst}"
    echo -e "${bldyel}>>> Installing sinatra gem using gem${txtrst}"
    sudo gem install sinatra -v 2.2.2 || die
    echo -e "${bldyel}>>> Spawning uWSGI rack app${txtrst}"
    echo -en "${bldred}"
    ./uwsgi --master --plugin 0:$1 --http :8080 --exit-on-reload --touch-reload reload.txt --rack $2 --daemonize uwsgi.log
    echo -en "${txtrst}"
    http_test "http://localhost:8080/hi"
    echo -e "${bldyel}===================== DONE $1 $2 =====================${txtrst}\n\n"
}


while read PV ; do
    for WSGI_FILE in tests/staticfile.py tests/testworkers.py tests/testrpc.py tests/testyieldnone.py ; do
        test_python $PV $WSGI_FILE
    done
done < <(cat "$CI_CONFIG" | grep "plugins/python base" | sed s_".*plugins/python base "_""_g)
while read PV ; do
    for INI_FILE in tests/deadlocks/*.ini ; do
        test_python_deadlocks $PV $INI_FILE
    done
done < <(cat "$CI_CONFIG" | grep "plugins/python base" | sed s_".*plugins/python base "_""_g)
while read RV ; do
    for RACK in examples/config2.ru ; do
        test_rack $RV $RACK
    done
done < <(cat "$CI_CONFIG" | grep "plugins/rack base" | sed s_".*plugins/rack base "_""_g)


echo "${bldgre}>>> $SUCCESS SUCCESSFUL TEST(S)${txtrst}"
if [ $ERROR -ge 1 ]; then
    echo "${bldred}>>> $ERROR FAILED TEST(S)${txtrst}"
    exit 1
fi

exit 0

