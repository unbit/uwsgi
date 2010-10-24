require('sputnik')
return sputnik.wsapi_app.new{
   VERSIUM_STORAGE_MODULE = "versium.sqlite3", 
   VERSIUM_PARAMS = {'/tmp/sputnik.db'},
   SHOW_STACK_TRACE = true,
   TOKEN_SALT = 'xxx',
   BASE_URL       = '/',
}

