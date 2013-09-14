#include "common.h"

extern struct uwsgi_tuntap utt;

int uwsgi_tuntap_firewall_check(struct uwsgi_tuntap_firewall_rule *direction, char *pkt, uint16_t len) {
        // sanity check
        if (len < 20) return -1;
        uint32_t *src_ip = (uint32_t *) &pkt[12];
        uint32_t *dst_ip = (uint32_t *) &pkt[16];

        uint32_t src = *src_ip;
        uint32_t dst = *dst_ip;

        struct uwsgi_tuntap_firewall_rule *utfr = direction;
        while(utfr) {
                if (utfr->src) {
                        uint32_t src_masked = src & utfr->src_mask;
                        if (!src_masked != utfr->src) goto next;
                }

                if (utfr->dst) {
                        uint32_t dst_masked = dst & utfr->dst_mask;
                        if (!dst_masked != utfr->dst) goto next;
                }

                return utfr->action;
next:
                utfr = utfr->next;
        }

        return 0;
}

