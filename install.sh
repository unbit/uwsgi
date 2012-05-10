echo "*** uWSGI installer ***"
if [ $# -ne 2 ]
then
  echo "Usage: install.sh <profile> <binary_path>"
  exit 1
fi

if [ ${2:0:1} != "/" ]
then
  echo "uWSGI binary path must be absolute !!!"
  exit 1
fi

echo "downloading latest uWSGI tarball..."
curl -o uwsgi_latest_from_installer.tar.gz http://projects.unbit.it/downloads/uwsgi-latest.tar.gz
mkdir uwsgi_latest_from_installer
tar zvxC uwsgi_latest_from_installer --strip-components=1 -f uwsgi_latest_from_installer.tar.gz
cd uwsgi_latest_from_installer
UWSGI_PROFILE="$1" UWSGI_BIN_NAME="$2" make
