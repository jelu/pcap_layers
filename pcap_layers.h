/*
 * Copyright (c) 2016 Duane Wessels and The Measurement Factory, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __pcap_layers_pcap_layers_h
#define __pcap_layers_pcap_layers_h

#include <pcap/pcap.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#ifdef HAVE_NETINET_IP_COMPAT_H
#include <netinet/ip_compat.h>
#endif

/* The following macros are similar to [nh]to[hn][ls](), except that the
 * network-ordered integer is referred to by a pointer, and does not need to
 * be aligned.  This is very handy and efficient when reading protocol
 * headers, e.g.
 *   uint16_t sport = nptohs(&udp->th_sport);
 * Note that it's ok to take the ADDRESS of members of unaligned structures,
 * just never try to use the VALUE of the member.
 */

/* Convert the network order 32 bit integer pointed to by p to host order.
 * p does not have to be aligned. */
#define nptohl(p) \
   ((((uint8_t*)(p))[0] << 24) | \
    (((uint8_t*)(p))[1] << 16) | \
    (((uint8_t*)(p))[2] << 8) | \
    ((uint8_t*)(p))[3])

/* Convert the network order 16 bit integer pointed to by p to host order.
 * p does not have to be aligned. */
#define nptohs(p) \
   ((((uint8_t*)(p))[0] << 8) | ((uint8_t*)(p))[1])

/* Copy the host order 16 bit integer in x into the memory pointed to by p
 * in network order.  p does not have to be aligned. */
#define htonps(p, x) \
    do { \
        ((uint8_t*)(p))[0] = (x & 0xFF00) >> 8; \
        ((uint8_t*)(p))[1] = (x & 0x00FF) >> 0; \
    } while (0)

/* Copy the host order 32 bit integer in x into the memory pointed to by p
 * in network order.  p does not have to be aligned. */
#define htonpl(p, x) \
    do { \
        ((uint8_t*)(p))[0] = (x & 0xFF000000) >> 24; \
        ((uint8_t*)(p))[1] = (x & 0x00FF0000) >> 16; \
        ((uint8_t*)(p))[2] = (x & 0x0000FF00) >> 8; \
        ((uint8_t*)(p))[3] = (x & 0x000000FF) >> 0; \
    } while (0)

typedef int l7_callback(const u_char *, int , void *);

extern int (*callback_ether) (const u_char * pkt, int len, void *userdata);
extern int (*callback_vlan) (unsigned short vlan, void *userdata);
extern int (*callback_ipv4) (const struct ip *ipv4, int len, void *userdata);
extern int (*callback_ipv6) (const struct ip6_hdr *ipv6, int len, void *userdata);
extern int (*callback_gre) (const u_char *pkt, int len, void *userdata);
extern int (*callback_tcp) (const struct tcphdr *tcp, int len, void *userdata);
extern int (*callback_udp) (const struct udphdr *udp, int len, void *userdata);
extern int (*callback_tcp_sess) (const struct tcphdr *tcp, int len, void *userdata, l7_callback *);
extern int (*callback_l7) (const u_char * l7, int len, void *userdata);

extern void handle_pcap(u_char * userdata, const struct pcap_pkthdr *hdr, const u_char * pkt);
extern int pcap_layers_init(int dlt, int reassemble);
extern void pcap_layers_clear_fragments(time_t older_then);

#endif /* __pcap_layers_pcap_layers_h */
