-module(uwsgi).
-export([encode/1,send/3]).

	
encode(Vars) ->
	Body = lists:map(fun(X) -> Len = length(X), lists:append( binary_to_list(<<Len:16/little-unsigned-integer>>), X) end, Vars),
	lists:flatten(Body).
	
response(Sock, Output) ->
	case gen_tcp:recv(Sock,0) of
		{ ok, Data } ->
			response(Sock, lists:append(Output, binary_to_list(Data)));
		{ error, closed } ->
			gen_tcp:close(Sock),
			Output
	end.

send(Host, Port, Message) ->
	{ ok, Sock } = gen_tcp:connect( Host, Port, [ binary, { active, false} ]),

	Body = encode(Message),

	Len = length(Body),

	ok = gen_tcp:send(Sock, << 0, Len:16/little-unsigned-integer, 0>>),

	ok = gen_tcp:send(Sock, Body),

	response(Sock, []).

