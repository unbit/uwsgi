# based on uwsgidecorators.py

def get_free_signal()
  for signum in 0..255
    if not UWSGI.signal_registered(signum)
      return signum
    end
  end
end

def timer(secs, target='', &block)
  freesig = get_free_signal
  UWSGI.register_signal(freesig, target, block)
  UWSGI.add_timer(freesig, secs)
end

def rbtimer(secs, target='', &block)
  freesig = get_free_signal
  UWSGI.register_signal(freesig, target, block)
  UWSGI.add_rb_timer(freesig, secs)
end

def filemon(file, target='', &block)
  freesig = get_free_signal
  UWSGI.register_signal(freesig, target, block)
  UWSGI.add_file_monitor(freesig, file)
end

def cron(minute, hour, day, month, dayweek, target='', &block)
  freesig = get_free_signal
  UWSGI.register_signal(freesig, target, block)
  UWSGI.add_cron(freesig, minute, hour, day, month, dayweek)
end
