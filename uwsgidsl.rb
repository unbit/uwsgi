# based on uwsgidecorators.py

if UWSGI.masterpid == 0
    raise "you have to enable the uWSGI master process to use this module"
end

def get_free_signal()
  for signum in 0..255
    if not UWSGI.signal_registered(signum)
      return signum
    end
  end
end

$postfork_chain = []
$mulefunc_list = []
$spoolfunc_list = []

module UWSGI
  module_function
  def post_fork_hook()
    $postfork_chain.each {|func| func.call }
  end

  module_function
  def spooler(args)
    $spoolfunc_list[args['ud_spool_func'].to_i].call(args)
  end

  module_function
  def mule_msg_hook(message)
    service = Marshal.load(message)
    if service['service'] == 'uwsgi_mulefunc'
      mulefunc_manager(service)
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

def signal(signum, target='', &block)
  UWSGI.register_signal(signum, target, block)
end

def postfork(&block)
  $postfork_chain << block
end

class SpoolProc < Proc
  def initialize(&block)
    @block = block
    @id = (($spoolfunc_list << block).length-1).to_s
  end

  def call(args)
    args['ud_spool_func'] = @id
    UWSGI::send_to_spooler(args)
  end
end

def rpc(name, &block)
  if block.arity <= 0
    UWSGI.register_rpc(name, block, 0)
  else
    UWSGI.register_rpc(name, block, block.arity)
  end
end

def mulefunc_manager(service)
  $mulefunc_list[service['func']].real_call(service['args'])
end

class MuleFunc < Proc

  def initialize(id=0, &block)
    @id = id
    @block = block
    @func_pos = (($mulefunc_list << self).length)-1
  end

  def real_call(*args)
    @block.call(*args)
  end

  def call(*args)
    UWSGI.mule_msg( Marshal.dump( {
                'service' => 'uwsgi_mulefunc',
                'func' => @func_pos,
                'args'=> args
            }), @id)
  end

end

class MuleProc < Proc
  def initialize(id, block)
    @id = id
    @block = block
  end

  def call()
    if UWSGI.mule_id == @id
      @block.call
    end
  end
end

class MuleLoopProc < MuleProc
  def call()
    if UWSGI.mule_id == @id
      loop do
        @block.call
      end
    end
  end
end

def mule(id, &block)
  $postfork_chain << MuleProc.new(id, block)
end

def muleloop(id, &block)
  $postfork_chain << MuleLoopProc.new(id, block)
end
