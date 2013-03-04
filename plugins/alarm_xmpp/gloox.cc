#include "../../uwsgi.h"
#include <gloox/client.h>
#include <gloox/error.h>
#include <gloox/message.h>
#include <gloox/connectionlistener.h>
#include <gloox/connectiontcpclient.h>

extern struct uwsgi_server uwsgi;

using namespace gloox;

class Jabbo : public ConnectionListener{

	public:

	Jabbo(struct uwsgi_thread *ut, char *jab_username, char *jab_password, char *dests) {

		u_thread = ut;
		dest = NULL;

		char *ctx = NULL;
		char *p = strtok_r(dests, ",", &ctx);
		while(p) {
			uwsgi_string_new_list(&dest, p);
			p = strtok_r(NULL, ",", &ctx);
		}

		full_jid = jab_username;

        	JID jid(jab_username);
        	client = new Client( jid, jab_password );
        	client->registerConnectionListener(this);
		u_connected = 0;
        	client->connect(false);
        	fd = static_cast<ConnectionTCPClient*>( client->connectionImpl() )->socket();
	}

	~Jabbo() {
        	delete client;
	}

	void send(char *buf, size_t len) {
		struct uwsgi_string_list *usl = dest;
		while(usl) {
			JID jid(usl->value);
			std::string text(buf, len);
			Message msg(Message::Chat, jid, text);
			client->send(msg);
			usl = usl->next;
		}
	}

	virtual void onConnect() {
		event_queue_add_fd_read(u_thread->queue, fd);
		event_queue_add_fd_read(u_thread->queue, u_thread->pipe[1]);
		u_connected = 1;
		uwsgi_log_alarm("-xmpp] (%s) connected to the XMPP server\n", full_jid);
    	}

    	virtual void onDisconnect(ConnectionError e) {
		uwsgi_log_alarm("-xmpp] (%s) trying reconnect to the XMPP server...\n", full_jid);
		if (u_connected) {
			// no need to remove it as it is already closed...
			//event_queue_del_fd(u_thread->queue, fd, event_queue_read());
			event_queue_del_fd(u_thread->queue, u_thread->pipe[1], event_queue_read());
		}
        	sleep(1);
		u_connected = 0;
        	client->connect(false);
        	fd = static_cast<ConnectionTCPClient*>( client->connectionImpl() )->socket();
    	}

	virtual void onResourceBindError(const Error *error) {
		uwsgi_log_alarm("-xmpp] (%s) onResourceBindError(): %s\n", full_jid, error->text().c_str());
		client->disconnect();
	}

	virtual void onSessionCreateError(const Error *error) {
		uwsgi_log_alarm("-xmpp] (%s) onSessionCreateError(): %s\n", full_jid, error->text().c_str());
		client->disconnect();
	}

	virtual bool onTLSConnect(const CertInfo& info) {
		return true;
	}

	Client* client;
	char *full_jid;
	int fd;
	int u_connected;
	struct uwsgi_thread *u_thread;
	struct uwsgi_string_list *dest;
};


extern "C" void uwsgi_alarm_xmpp_loop(struct uwsgi_thread *ut) {

        int interesting_fd;

        ut->buf = (char *) uwsgi_malloc(uwsgi.log_master_bufsize);

	char *xmpp_username = (char *) "";
	char *xmpp_password = (char *) "";
	char *xmpp_dests = (char *) "";

        // 0 -> username, 1 -> password, 2-> dest list
        int opt_state = 0;
        // fill xmpp options
        char *ctx = NULL;
        char *opts = uwsgi_str((char *)ut->data);
        char *p = strtok_r(opts, ";", &ctx);
        while(p) {
                switch(opt_state) {
                        case 0:
                                xmpp_username = p;
                                opt_state = 1;
                                break;
                        case 1:
                                xmpp_password = p;
                                opt_state = 2;
                                break;
                        case 2:
                                xmpp_dests = p;
                                opt_state = 3;
                                break;
                        default:
                                break;
                }
                p = strtok_r(NULL, ";", &ctx);
        }

	// do not process loglines til the jabber account is connected
	event_queue_del_fd(ut->queue, ut->pipe[1], event_queue_read());

	Jabbo j(ut, xmpp_username, xmpp_password, xmpp_dests);	

	int timeout = 0;

        for(;;) {
		if (j.u_connected) {
			timeout = -1;
		}
		else {
			timeout = 0;
		}
                int ret = event_queue_wait(ut->queue, timeout, &interesting_fd);           
                if (ret < 0) continue;

                if (ret > 0 && interesting_fd == ut->pipe[1]) {
                        ssize_t rlen = read(ut->pipe[1], ut->buf, uwsgi.log_master_bufsize);
                        if (rlen <= 0) continue;
			if (j.u_connected) {
				j.send(ut->buf, rlen);
			}
                }
		else if (ret == 0 || (ret > 0 && j.fd > -1 && interesting_fd == j.fd)) {
			j.client->recv();
		}
        }
}

