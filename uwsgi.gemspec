Gem::Specification.new do |s|
  s.name        = 'uwsgi'
  s.license     = 'GPL-2'
  s.version     = `python -c "import uwsgiconfig as uc; print uc.uwsgi_version"`.sub(/-dev-.*/,'')
  s.date        = '2025-06-03'
  s.summary     = "uWSGI"
  s.description = "The uWSGI server for Ruby/Rack"
  s.authors     = ["Unbit"]
  s.email       = 'info@unbit.it'
  s.extensions  = ['ext/uwsgi/extconf.rb']
  s.files       = []
  s.require_paths = ['.']
  s.executables << 'uwsgi'
  s.homepage    = 'http://projects.unbit.it/uwsgi'
  s.add_runtime_dependency 'rack'
end
