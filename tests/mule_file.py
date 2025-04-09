# uwsgi --master --plugins=python --mule=mule_file.py -s:0 
import uwsgi
print(uwsgi.mule_file())
