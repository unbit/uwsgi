#!/bin/bash
set -u


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
        else
            SUCCESS=$((SUCCESS+1))
        fi
        die "${bldyel}>>> SUCCESS: Done${txtrst}"
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
    gem install sinatra || die
    echo -e "${bldyel}>>> Spawning uWSGI rack app${txtrst}"
    echo -en "${bldred}"
    ./uwsgi --master --plugin 0:$1 --http :8080 --exit-on-reload --touch-reload reload.txt --rack $2 --daemonize uwsgi.log
    echo -en "${txtrst}"
    http_test "http://localhost:8080/hi"
    echo -e "${bldyel}===================== DONE $1 $2 =====================${txtrst}\n\n"
}


while read PV ; do
    for WSGI_FILE in tests/staticfile.py tests/testworkers.py tests/testrpc.py ; do
        test_python $PV $WSGI_FILE
    done
done < <(cat .travis.yml | grep "plugins/python base" | sed s_".*plugins/python base "_""_g)


while read RV ; do
    for RACK in examples/config2.ru ; do
        test_rack $RV $RACK
    done
done < <(cat .travis.yml | grep "plugins/rack base" | sed s_".*plugins/rack base "_""_g)


echo "${bldgre}>>> $SUCCESS SUCCESSFUL TEST(S)${txtrst}"
if [ $ERROR -ge 1 ]; then
    echo "${bldred}>>> $ERROR FAILED TEST(S)${txtrst}"
    exit 1
fi

exit 0

