/* 
 * jprobe_simple.c.c
 * Copyright (C) 2013 Chaitanya H. <C@24.IO>
 * Version 1.0: Tue Feb 12 09:40:58 PST 2013
 * 
 * This file is a simple "Hello World" implementation of kprobe jprobe.
 * I am using it to study the Linux TCP/IP stack flow through the Linux kernel.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * 
 * Code from: http://www.linuxforu.com/2011/04/kernel-debugging-using-kprobe-and-jprobe/
 * Machine: 3.2.0-37-generic
 *
 */

#include<linux/module.h> 
#include<linux/version.h> 
#include<linux/kernel.h> 
#include<linux/init.h> 
#include<linux/kprobes.h> 
#include<net/ip.h> 
 
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Chaitanya H <C@24.IO>");
MODULE_DESCRIPTION("Hello World implementation of kprobe jprobe");
MODULE_ALIAS("kprobe_simple");

//Bringing this back just so that this can compile and I can see things. 

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"


/* Proxy routine having the same arguments as actual ip_recv() routine */
//int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
int ip_rcv_handler (struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
	
    	struct iphdr *my_iph;
    	struct tcphdr *my_tcph;
   	u32 S_ip,D_ip;
    	u16 P_id;
    	u16 S_prt, D_prt;
    	u32 Seq_num, Ack_num;

	//Logic to dissect and use the sk_buff structure we get this function.
	//We will use this next for checking which packet we are talking about

    	my_iph = ip_hdr(skb);
    	my_tcph = tcp_hdr(skb);

    	S_prt = my_tcph->source;
    	D_prt = my_tcph->dest;
    	Seq_num = my_tcph->seq;
    	Ack_num = my_tcph->ack_seq;

    	S_ip = my_iph->saddr;
    	D_ip = my_iph->daddr;
    	P_id = my_iph->id;

    	printk("Tuple: "NIPQUAD_FMT,NIPQUAD(S_ip));
    	printk(":%d",S_prt);
    	printk("-"NIPQUAD_FMT,NIPQUAD(D_ip));
    	printk(":%d ",D_prt);

   	printk(" ID - %d Seq - %d Ack - %d", P_id, Seq_num, Ack_num);

    	//Tuple: SIP:SPORT DIP:DPORT
    	//ID: IP-ID
    	//SEQ: TCP-SEQ:TCP-ACK

        /* Always end with a call to jprobe_return(). */
        jprobe_return();
        return 0;
}

static struct jprobe my_jprobe = {
        .entry                  = ip_rcv_handler,
        .kp = {
                .symbol_name    = "ip_rcv",
        },
};


static int __init jprobe_init(void)
{
        int ret;

        ret = register_jprobe(&my_jprobe);
        if (ret < 0) {
                printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
                return -1;
        }
        printk(KERN_INFO "Planted jprobe at %p, handler addr %p\n",
               my_jprobe.kp.addr, my_jprobe.entry);
        return 0;
}

static void __exit jprobe_exit(void)
{
        unregister_jprobe(&my_jprobe);
        printk(KERN_INFO "jprobe at %p unregistered\n", my_jprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");


