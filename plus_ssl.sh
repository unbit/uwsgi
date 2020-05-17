#!/bin/sh
# this needs to be in the environment when compiling the plugins
set -e
export C_INCLUDE_PATH=/usr/local/opt/openssl\@1.1/include
make PROFILE=nolang
install_name_tool ./uwsgi -add_rpath /usr/local/opt/openssl\@1.1/lib/
