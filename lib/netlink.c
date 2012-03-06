#include "../uwsgi.h"

#ifdef OBSOLETE_LINUX_KERNEL
#ifndef __u16
#define __u16           u_int16_t
#endif
#ifndef __u32
#define __u32           u_int32_t
#endif
#ifndef __s32
#define __s32           int32_t
#endif
#ifndef __u8
#define __u8           u_int8_t
#endif
#endif

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#ifdef CLONE_NEWNET

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#ifndef VETH_INFO_PEER
# define VETH_INFO_PEER 1
#endif


struct uwsgi_nl_req {
	struct nlmsghdr nlmsg;
	struct ifinfomsg ifinfomsg;
};

struct uwsgi_nl_ipreq {
	struct nlmsghdr nlmsg;
	struct ifaddrmsg ifaddrmsg;
};

struct uwsgi_nl_rtreq {
	struct nlmsghdr nlmsg;
	struct rtmsg rtmsg;
};

int uwsgi_nl_send(struct nlmsghdr *);

struct nlmsghdr *uwsgi_netlink_alloc() {

	size_t len = NLMSG_ALIGN(8192) + NLMSG_ALIGN(sizeof(struct nlmsghdr *));

	struct nlmsghdr *nlmsg = (struct nlmsghdr *) uwsgi_malloc(len);

	memset(nlmsg, 0, len);

	struct uwsgi_nl_req *unr = (struct uwsgi_nl_req *)nlmsg;
        unr->ifinfomsg.ifi_family = AF_UNSPEC;

	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsg_type = RTM_NEWLINK;
	nlmsg->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	
	return nlmsg;
}

struct nlmsghdr *uwsgi_netlink_ip_alloc() {

        size_t len = NLMSG_ALIGN(8192) + NLMSG_ALIGN(sizeof(struct nlmsghdr *));

        struct nlmsghdr *nlmsg = (struct nlmsghdr *) uwsgi_malloc(len);

        memset(nlmsg, 0, len);

        struct uwsgi_nl_ipreq *uni = (struct uwsgi_nl_ipreq *)nlmsg;
        uni->ifaddrmsg.ifa_family = AF_INET;
        uni->ifaddrmsg.ifa_scope = 0;

        nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        nlmsg->nlmsg_type = RTM_NEWADDR;
        nlmsg->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL;
	

        return nlmsg;
}

struct nlmsghdr *uwsgi_netlink_rt_alloc() {

        size_t len = NLMSG_ALIGN(8192) + NLMSG_ALIGN(sizeof(struct nlmsghdr *));

        struct nlmsghdr *nlmsg = (struct nlmsghdr *) uwsgi_malloc(len);

        memset(nlmsg, 0, len);

        struct uwsgi_nl_rtreq *unr = (struct uwsgi_nl_rtreq *)nlmsg;
        unr->rtmsg.rtm_family = AF_INET;
	unr->rtmsg.rtm_table = RT_TABLE_MAIN;
	unr->rtmsg.rtm_protocol = RTPROT_STATIC;
        unr->rtmsg.rtm_scope = RT_SCOPE_UNIVERSE;
        unr->rtmsg.rtm_type = RTN_UNICAST;
	

        nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
        nlmsg->nlmsg_type = RTM_NEWROUTE;
        nlmsg->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL;


        return nlmsg;
}

int uwsgi_netlink_rt(char *src, char *dst, int dst_prefix, char *gw) {

	struct nlmsghdr *nlmsg = uwsgi_netlink_rt_alloc();
        struct rtattr *rta;
        struct in_addr ia;
        struct in_addr oa;
        struct in_addr ga;
	struct uwsgi_nl_rtreq *unr = (struct uwsgi_nl_rtreq *)nlmsg;

        if (inet_pton(AF_INET, src, &ia) <= 0) {
                uwsgi_error("inet_pton()");
                free(nlmsg);
                return -1;
        }

        if (inet_pton(AF_INET, dst, &oa) <= 0) {
                uwsgi_error("inet_pton()");
                free(nlmsg);
                return -1;
        }

        if (inet_pton(AF_INET, gw, &ga) <= 0) {
                uwsgi_error("inet_pton()");
                free(nlmsg);
                return -1;
        }

        rta = NLMSG_TAIL(nlmsg);
        rta->rta_type = RTA_PREFSRC;
        rta->rta_len = RTA_LENGTH(4);
        memcpy(RTA_DATA(rta), &ia.s_addr, 4);
        nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

        rta = NLMSG_TAIL(nlmsg);
        rta->rta_type = RTA_DST;
        rta->rta_len = RTA_LENGTH(4);
        memcpy(RTA_DATA(rta), &oa.s_addr, 4);
        nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

        rta = NLMSG_TAIL(nlmsg);
        rta->rta_type = RTA_GATEWAY;
        rta->rta_len = RTA_LENGTH(4);
        memcpy(RTA_DATA(rta), &ga.s_addr, 4);
        nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

	unr->rtmsg.rtm_src_len = 0; 
	unr->rtmsg.rtm_dst_len = dst_prefix;

        return uwsgi_nl_send(nlmsg);
}

int uwsgi_netlink_gw(char *iface, char *ip) {

        struct nlmsghdr *nlmsg = uwsgi_netlink_rt_alloc();
        struct rtattr *rta;
        struct in_addr ia;
	uint32_t zero = 0;

        int index = if_nametoindex(iface);
        if (!index) return -1;

        if (inet_pton(AF_INET, ip, &ia) <= 0) {
                uwsgi_error("inet_pton()");
                free(nlmsg);
                return -1;
        }

	
        rta = NLMSG_TAIL(nlmsg);
        rta->rta_type = RTA_GATEWAY;
        rta->rta_len = RTA_LENGTH(4);
        memcpy(RTA_DATA(rta), &ia.s_addr, 4);
        nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

        rta = NLMSG_TAIL(nlmsg);
        rta->rta_type = RTA_DST;
        rta->rta_len = RTA_LENGTH(4);
        memcpy(RTA_DATA(rta), &zero, 4);
        nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

        rta = NLMSG_TAIL(nlmsg);
        rta->rta_type = RTA_OIF;
        rta->rta_len = RTA_LENGTH(sizeof(int));
        memcpy(RTA_DATA(rta), &index, sizeof(int));
        nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

        return uwsgi_nl_send(nlmsg);
}


int uwsgi_netlink_ip(char *iface, char *ip, int prefix) {

	struct nlmsghdr *nlmsg = uwsgi_netlink_ip_alloc();
        struct uwsgi_nl_ipreq *uni = (struct uwsgi_nl_ipreq *)nlmsg;
        struct rtattr *rta;
	struct in_addr ia;

        int index = if_nametoindex(iface);
        if (!index) return -1;

        uni->ifaddrmsg.ifa_index = index;
        uni->ifaddrmsg.ifa_prefixlen = prefix;
	
	if (inet_pton(AF_INET, ip, &ia) <= 0) {
		uwsgi_error("inet_pton()");
		free(nlmsg);
		return -1;
	}

        rta = NLMSG_TAIL(nlmsg);
        rta->rta_type = IFA_LOCAL;
        rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
        memcpy(RTA_DATA(rta), &ia, sizeof(struct in_addr));
        nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

        rta = NLMSG_TAIL(nlmsg);
        rta->rta_type = IFA_ADDRESS;
        rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
        memcpy(RTA_DATA(rta), &ia, sizeof(struct in_addr));
        nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

        return uwsgi_nl_send(nlmsg);
}

int uwsgi_netlink_veth_attach(char *veth1, pid_t pid) {

	struct nlmsghdr *nlmsg = uwsgi_netlink_alloc();
	struct uwsgi_nl_req *unr = (struct uwsgi_nl_req *)nlmsg;
	struct rtattr *rta;

	int index = if_nametoindex(veth1);
	if (!index) return -1;

	unr->ifinfomsg.ifi_index = index;

	rta = NLMSG_TAIL(nlmsg);
	rta->rta_type = IFLA_NET_NS_PID;
	rta->rta_len = RTA_LENGTH(sizeof(pid_t));
	memcpy(RTA_DATA(rta), &pid, sizeof(pid_t));
	nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

	return uwsgi_nl_send(nlmsg);
	
}

int uwsgi_netlink_ifup(char *iface) {

        struct nlmsghdr *nlmsg = uwsgi_netlink_alloc();
        struct uwsgi_nl_req *unr = (struct uwsgi_nl_req *)nlmsg;

        int index = if_nametoindex(iface);
        if (!index) return -1;

        unr->ifinfomsg.ifi_index = index;
	unr->ifinfomsg.ifi_change |= IFF_UP;
	unr->ifinfomsg.ifi_flags |= IFF_UP;	
        return uwsgi_nl_send(nlmsg);

}

int uwsgi_netlink_del(char *iface) {

        struct nlmsghdr *nlmsg = uwsgi_netlink_alloc();
        struct uwsgi_nl_req *unr = (struct uwsgi_nl_req *)nlmsg;

        int index = if_nametoindex(iface);
        if (!index) return -1;

	nlmsg->nlmsg_type = RTM_DELLINK;
        unr->ifinfomsg.ifi_index = index;
        return uwsgi_nl_send(nlmsg);

}



int uwsgi_netlink_veth(char *veth0, char *veth1) {

	struct rtattr *rta, *rta0, *rta1, *rta2;
	
	struct nlmsghdr *nlmsg = uwsgi_netlink_alloc();

	nlmsg->nlmsg_flags |= NLM_F_CREATE|NLM_F_EXCL;

	// IFLA_LINKINFO
	rta0 = NLMSG_TAIL(nlmsg);
	rta0->rta_type = IFLA_LINKINFO;
	rta0->rta_len = RTA_LENGTH(0);
	nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta0->rta_len);

	// IFLA_INFO_KIND
	rta = NLMSG_TAIL(nlmsg);
	rta->rta_type = IFLA_INFO_KIND;
	rta->rta_len = RTA_LENGTH(4);
	memcpy(RTA_DATA(rta), "veth", 4);
	nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

	// IFLA_INFO_DATA
	rta1 = NLMSG_TAIL(nlmsg);
	rta1->rta_type = IFLA_INFO_DATA;
	rta1->rta_len = RTA_LENGTH(0);
	nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta1->rta_len);

	// VETH_INFO_PEER
	rta2 = NLMSG_TAIL(nlmsg);
	rta2->rta_type = VETH_INFO_PEER;
	rta2->rta_len = RTA_LENGTH(0);
	nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta2->rta_len);

	nlmsg->nlmsg_len += sizeof(struct ifinfomsg);

	// IFLA_IFNAME
	rta = NLMSG_TAIL(nlmsg);
	rta->rta_type = IFLA_IFNAME;
	rta->rta_len = RTA_LENGTH(strlen(veth1));
	memcpy(RTA_DATA(rta), veth1, strlen(veth1));
	nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

	rta2->rta_len = (void *)NLMSG_TAIL(nlmsg) - (void *)rta2;
	rta1->rta_len = (void *)NLMSG_TAIL(nlmsg) - (void *)rta1;
	rta0->rta_len = (void *)NLMSG_TAIL(nlmsg) - (void *)rta0;

	// IFLA_IFNAME
	rta = NLMSG_TAIL(nlmsg);
	rta->rta_type = IFLA_IFNAME;
	rta->rta_len = RTA_LENGTH(strlen(veth0));
	memcpy(RTA_DATA(rta), veth0, strlen(veth0));
	nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

	return uwsgi_nl_send(nlmsg);	
}

int uwsgi_nl_send(struct nlmsghdr *nlmsg) {

	struct sockaddr_nl nladdr;

	struct iovec iov = {
                .iov_base = (void*)nlmsg,
                .iov_len = nlmsg->nlmsg_len,
        };

	struct msghdr msg = {
                .msg_name = &nladdr,
                .msg_namelen = sizeof(nladdr),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        int ret;	
	int nlfd;

	memset(&nladdr, 0, sizeof(struct sockaddr_nl));
        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = 0;
        nladdr.nl_groups = 0;

	nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlfd < 0) {
		uwsgi_error("socket()");
		free(nlmsg);
		return -1;
	}

	ret = sendmsg(nlfd, &msg, 0);
	if (ret < 0) {
		uwsgi_error("sendmsg()");
		free(nlmsg);
		close(nlfd);
		return -1;
	}
	ret = recvmsg(nlfd, &msg, 0);
	if (ret < 0) {
		uwsgi_error("recvmsg()");
		free(nlmsg);
		close(nlfd);
		return -1;
	}

	if (nlmsg->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(nlmsg);
                ret = err->error;
        }

	free(nlmsg);
	close(nlfd);
	return ret;
}
#endif
