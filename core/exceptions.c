/*

	Exceptions management

	generally exceptions are printed in the logs, but if you enable
	an exception manager they will be stored in a (relatively big) uwsgi packet
	with the following structure.

	"vars" -> keyval of request vars
	"backtrace" -> list of backtrace lines. Each line is a list of 5 elements filename,line,function,text,custom
	"unix" -> seconds since the epoch
	"class" -> the exception class
	"msg" -> a text message mapped to the extension
	"wid" -> worker id
	"core" -> the core generating the exception
	"pid" -> pid of the worker
	"node" -> hostname

	Other vars can be added, but you cannot be sure they will be used by exceptions handler.

	The exception-uwsgi packet is passed "as is" to the exception handler

*/
