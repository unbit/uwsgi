/*

	uWSGI Legions subsystem

	A Legion is a group of uWSGI instances sharing a single object. This single
	object can be owned only by the instance with the higher value. Such an instance is the
	Lord of the Legion. There can only be one (and only one) Lord for each Legion.
	If a member of a Legion spawns with an higher value than the current Lord, it became the new Lord.
	If two (or more) member of a legion have the same value, their name (read: ip address) is used as the delta
	for choosing the new Lord:

	each octect of the address + the port is summed to form the delta (192.168.0.1:4001 = 192 + 168 + 0 + 1 + 4001 = 4362).

	The delta number is a last resort, you should always give different values to the members of a Legion

	Legions options (the legion1 is formed by 4 nodes, only one node will get the ip address, this is an ip takeover implementation)

	// became a member of a legion (each legion uses a shared secret)
	legion = legion1 192.168.0.1:4001 100 mysecret
	// the other members of the legion
	legion-node = legion1 192.168.0.2:4001
	legion-node = legion1 192.168.0.3:4001
	legion-node = legion1 192.168.0.4:4001

	legion-lord = legion1 iptakeover:action=up,addr=192.168.0.100
	legion-unlord = legion1 iptakeover:action=down,addr=192.168.0.100

	legion-lord = legion1 cmd:foobar.sh up
	legion-lord = legion1 cmd:foobar.sh down

	TODO
	some option could benefit from the legions subsystem, expecially in clustered environments	
	Cron-tasks for exampel could be run only by the lord and so on...

	

*/
