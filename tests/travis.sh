#!/bin/bash


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
    echo -e "${bldyel}================== TESTING $1 =====================${txtrst}"
    echo -e "${bldyel}>>> Spawning uWSGI python app${txtrst}"
    echo -en "${bldred}"
    ./uwsgi --master --plugin 0:$1 --http :8080 --exit-on-reload --touch-reload reload.txt --wsgi-file tests/staticfile.py --daemonize uwsgi.log
    echo -en "${txtrst}"
    http_test "http://localhost:8080/"
    echo -e "${bldyel}===================== DONE $1 =====================${txtrst}\n\n"
}


test_rack() {
    date > reload.txt
    rm -f uwsgi.log
    echo -e "${bldyel}================== TESTING $1 =====================${txtrst}"
    case "$1" in
    "rack187")
        GEMS_BINARY="/usr/bin/gem1.8"
        ;;
    "rack191")
        GEMS_BINARY="/usr/bin/gem1.9.1"
        ;;
    "rack193")
        GEMS_BINARY="/usr/bin/gem1.9.3"
        ;;
    esac
    echo -e "${bldyel}>>> Installing sinatra gem using ${GEMS_BINARY}${txtrst}"
    $GEMS_BINARY install sinatra || die
    echo -e "${bldyel}>>> Spawning uWSGI rack app${txtrst}"
    echo -en "${bldred}"
    ./uwsgi --master --plugin 0:$1 --http :8080 --exit-on-reload --touch-reload reload.txt --rack examples/config2.ru --daemonize uwsgi.log
    echo -en "${txtrst}"
    http_test "http://localhost:8080/hi"
    echo -e "${bldyel}===================== DONE $1 =====================${txtrst}\n\n"
}


while read PV ; do
    test_python $PV
done < <(cat .travis.yml | grep "plugins/python base" | sed s_".*plugins/python base "_""_g)


while read RV ; do
    test_rack $RV
done < <(cat .travis.yml | grep "plugins/rack base" | sed s_".*plugins/rack base "_""_g)


echo "${bldgre}>>> $SUCCESS SUCCESSFUL PLUGIN(S)${txtrst}"
if [ $ERROR -ge 1 ]; then
    echo "${bldred}>>> $ERROR FAILED PLUGIN(S)${txtrst}"
    exit 1
fi

exit 0

