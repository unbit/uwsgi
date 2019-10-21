FROM ubuntu:xenial

# The default ubuntu mirrors aren't particularly fast (at least in my location). 
# You can add a mirror host in a file named 'mirror.local.txt' in this
# directory that will be used to edit the mirror used in /etc/apt/sources.list .
# Example contents: 
# http://mirrors.rit.edu/ubuntu/
COPY mirror.local* /tmp
RUN /bin/bash -c '[ ! -e /tmp/mirror.local.txt ] || { mirror=$(< /tmp/mirror.local.txt) ; sed -i"" -n "/^deb/s| http[^ ]*| $mirror|p" /etc/apt/sources.list ; }' 

RUN apt-get update -q
RUN apt-get install -qyf software-properties-common

# https://askubuntu.com/questions/490468/add-apt-repository-throws-python-error-unicodedecodeerror-ascii-codec-cant 
RUN LC_ALL=C.UTF-8 add-apt-repository ppa:deadsnakes/ppa -y
RUN LC_ALL=C.UTF-8 add-apt-repository ppa:ondrej/php -y

RUN apt-get update -q

RUN apt-get install -qyf python2.6-dev python3.4-dev python3.5-dev python3.6-dev \
                         libxml2-dev libpcre3-dev libcap2-dev \
                         php7.2-dev libphp7.2-embed libargon2-0-dev libsodium-dev \
                         liblua5.1-0-dev \
                         libjansson-dev libldap2-dev libpq-dev \
                         libpam0g-dev libsqlite3-dev libyaml-dev \
                         libzmq-dev libmatheval-dev libperl-dev \
                         libonig-dev libdb-dev libqdbm-dev libbz2-dev \
                         libwrap0-dev libgeoip-dev libv8-dev libxslt1-dev \
                         libboost-thread-dev libboost-filesystem-dev \
                         libssl-dev libacl1-dev python-greenlet-dev \
                         openjdk-8-jdk libgloox-dev gccgo \
                         cli-common-dev mono-devel mono-mcs uuid-dev \
                         curl check
