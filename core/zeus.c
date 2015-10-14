#include <uwsgi.h>

/*

	*** WORK IN PROGRESS ***

	Zeus mode

	A Zeus instance can load all of the available imperial monitor plugins, but instead of spawning
	vassals it delegates actions to Emperors connected to it.

	The Zeus instance try to distribute vassals evenly between Emperors.

	Emperors register to one (ore more, maybe...) Zeus instance, passing various informations (like the maximum number
	of vassals it can manage)

	to spawn a Zeus:


	# unencrypted mode
	uwsgi --zeus 192.168.173.17:4040 --emperor /etc/uwsgi/vassals
	# crypted mode
	uwsgi --zeus 192.168.173.17:4040,foobar.crt,foobar.key --emperor /etc/uwsgi/vassals
	# crypted + authentication mode
	uwsgi --zeus 192.168.173.17:4040,foobar.crt,foobar.key,clients.pem --emperor /etc/uwsgi/vassals


	to connect an Emperor to Zeus

	# unencrypted mode
	uwsgi --emperor zeus:192.168.173.17:4040
	# crypted mode
	uwsgi --emperor zeus-ssl:192.168.173.17:4040
	# crypted + authentication mode
	uwsgi --emperor zeus-ssl:192.168.173.17:4040,myself.key


	Protocol

	(each message is a basic uwsgi packet: modifier1 pktsize modifier2 payload)
	
	modifier2 identifies the type of the message

	0 -> I_AM_ALIVE {node: 'node001', max_vassals: '100', running_vassals: '17'} [ emperor -> zeus ]

	1 -> NEW_VASSAL {name: 'foobar.ini'} [ zeus -> the chosen emperor ]

	2 -> ACCEPTED_VASSAL {name: 'foobar.ini'} [ emperor -> zeus ]

        3 -> CONFIG_CHUNK {name: 'foobar.ini', body: '[uwsgi].....'} [ zeus -> the chosen emperor ]

	4 -> CONFIG_END {name: 'foobar.ini'} [ zeus -> the chosen emperor ]

	5 -> VASSAL_SPAWNED {name: 'foobar.ini'} [the chosen emperor -> zeus]

	6 -> VASSAL_REJECTED {name: 'foobar.ini'} [the chosen emperor -> zeus]

	7 -> VASSAL_RELOAD {name: 'foobar.ini'} [ zeus -> the chosen emperor ]

	8 -> VASSAL_UPDATE {name: 'foobar.ini'} [ zeus -> the chosen emperor ]

	9 -> VASSAL_DESTROY {name: 'foobar.ini'} [ zeus -> the chosen emperor ]

	10 -> VASSAL_RELOADED {name: 'foobar.ini'} [the chosen emperor -> zeus]

	11 -> VASSAL_DESTROYED {name: 'foobar.ini'} [the chosen emperor -> zeus]

*/

/*
	check how many nodes the instace needs (default 1)
*/

int uwsgi_zeus_spawn_instance(struct uwsgi_instance *ui) {
	int i, nodes = 1;
	char *how_many_nodes = vassal_attr_get(ui, "zeus-nodes");
	if (how_many_nodes) {	
		nodes = atoi(how_many_nodes);
	}
	for(i=0;i<nodes;i++) {
		// now start analyzing nodes, the one with most
		// free slots will be used

		// send NEW_VASSAL request to the node,
		// if it answers with ACCEPTED_VASSAL 
	}
	return 0;
}
