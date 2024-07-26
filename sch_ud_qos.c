// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/sch_ud_qos.c	Usage-Dependent Quality of Service.
 *
 * based on: 	net/sched/sch_prio.c
 *
 * Authors:	Jona Herrmann
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
//////////////
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
/////////////
#include <linux/hrtimer.h>
#include <linux/ktime.h>
/////////////
#include <linux/spinlock.h>

// Parameters
int INTERVAL_IN_S = 60;
// for monitoring
#define NUMBER_IPv4 5
#define NUMBER_IPv6 5
int MONITORING_SIZE = 190000; // number of packets in monitoring per IP
int UPDATE_PERIODE_IN_MS = 1000;
/////////////

struct dataRate_node_ipv6 {
	struct in6_addr ip;
	unsigned int dataRate;
};

struct dataRate_node_ipv4 {
	unsigned int ip;
	unsigned int dataRate;
};

struct packet {
	unsigned int size;
	u64 timestamp;
};

struct packet_buffer {
    struct packet * buffer;
   	int head;
    int maxlen;
};

struct monitoring_ipv6 {
	struct in6_addr ip;
	struct packet_buffer packet_buf;
};

struct monitoring_ipv4 {
	unsigned int ip;
	struct packet_buffer packet_buf;
};

// Variables for monitoring 
spinlock_t mon_lock_ipv4;
spinlock_t mon_lock_ipv6;
struct monitoring_ipv4 mon_ipv4[NUMBER_IPv4];
struct monitoring_ipv6 mon_ipv6[NUMBER_IPv6];


static void add_packet(struct packet_buffer *c, struct packet packet)
{
    int next;

    next = c->head + 1;  // next is where head will point to after this write.
    if (next >= c->maxlen)
        next = 0;

    c->buffer[c->head] = packet;
    c->head = next;
}

// Assuming the buffer is big enough for all packets
static unsigned int generate_dataRate(struct packet_buffer *c, u64 interval_in_ns)
{
	unsigned int sum = 0;
    int i = c->head - 1;
	if (i < 0)
		i = c->maxlen - 1;
	u64 now = ktime_get_ns();
	u64 actual;
	u64 last = 0;
	
	for (int k = 0; k < MONITORING_SIZE; k++)
	{
		actual = c->buffer[i].timestamp;
		
		// actual packet is newer -> not enough packets for intervall
		// -> should not happen
		if (actual > now)
		{
			break;
		}
		 
		// packet in interval?
		if (now - actual <= interval_in_ns)
		{
			sum += c->buffer[i].size;
		} else {
			break;
		}

		i -= 1;
		if (i < 0)
			i = c->maxlen - 1;
			
		last = actual;
    }

	// calculate average dataRate (byte per second)
	return sum / INTERVAL_IN_S;
}

struct prio_sched_data {
	int bands;
	struct Qdisc *queues[TCQ_PRIO_BANDS];
	struct hrtimer update_timer;
	u64 update_periode;
	struct dataRate_node_ipv4 dataRate_ipv4[NUMBER_IPv4];
	struct dataRate_node_ipv6 dataRate_ipv6[NUMBER_IPv6];
	unsigned int thresholds[TCQ_PRIO_BANDS];
};


static void set_dataRate_ipv6(struct in6_addr ip, unsigned int dataRate, struct dataRate_node_ipv6 struct_dataRate[NUMBER_IPv6])
{
	for(int i = 0; i < NUMBER_IPv6; i++)
	{
		if(ipv6_addr_equal(&ip, &struct_dataRate[i].ip))
		{
			struct_dataRate[i].dataRate = dataRate;
			break;
		}
		if(ipv6_addr_any(&struct_dataRate[i].ip))
		{
			struct_dataRate[i].ip = ip;
			struct_dataRate[i].dataRate = dataRate;
			break;
		}
	}
}

static void set_dataRate_ipv4(unsigned int ip, unsigned int dataRate, struct dataRate_node_ipv4 struct_dataRate[NUMBER_IPv4])
{
	for(int i = 0; i < NUMBER_IPv4; i++)
	{
		if(struct_dataRate[i].ip == ip)
		{
			struct_dataRate[i].dataRate = dataRate;
			break;
		}
		if(struct_dataRate[i].ip == 0)
		{
			struct_dataRate[i].ip = ip;
			struct_dataRate[i].dataRate = dataRate;
			break;
		}
	}
}

static unsigned int get_dataRate_ipv6(struct in6_addr ip, struct dataRate_node_ipv6 struct_dataRate[NUMBER_IPv6])
{
	for(int i = 0; i < NUMBER_IPv6; i++)
	{
		if(ipv6_addr_equal(&ip, &struct_dataRate[i].ip))
		{
			return struct_dataRate[i].dataRate;
		}
	}

	return 0;
}

static unsigned int get_dataRate_ipv4(unsigned int ip, struct dataRate_node_ipv4 struct_dataRate[NUMBER_IPv4])
{
	for(int i = 0; i < NUMBER_IPv4; i++)
	{
		if(struct_dataRate[i].ip == ip)
		{
			return struct_dataRate[i].dataRate;
		}
	}

	return 0;
}

static int get_dataRate_class(struct sk_buff *skb, struct Qdisc *sch)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	unsigned int dataRate;
	int prio;

	if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip_header = ipv6_hdr(skb);
		struct in6_addr src_ip = (struct in6_addr)ip_header->saddr;

		dataRate = get_dataRate_ipv6(src_ip, q->dataRate_ipv6);
 
		for (prio = 0; prio < q->bands; prio++) {
			if (dataRate < q->thresholds[prio])
			{
		    	return prio;
			}
		}
		
		return q->bands - 1;
	} else if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *ip_header = ip_hdr(skb);
		unsigned int src_ip = (unsigned int)ip_header->saddr;

		dataRate = get_dataRate_ipv4(src_ip, q->dataRate_ipv4);
		
		for (prio = 0; prio < q->bands; prio++) {
			if (dataRate < q->thresholds[prio])
			{
		    	return prio;
			}
		}
		
		return q->bands - 1;
	}

	return 0;
}

static enum hrtimer_restart update_dataRate(struct hrtimer *timer)
{
	struct prio_sched_data *q = container_of(timer, struct prio_sched_data, update_timer);

	for(int i = 0; i < NUMBER_IPv4; i++)
	{
		unsigned int dataRate = generate_dataRate(&mon_ipv4[i].packet_buf, (u64) INTERVAL_IN_S * 1000000000);    
		
		set_dataRate_ipv4(mon_ipv4[i].ip, dataRate, q->dataRate_ipv4);
	}
	
	for(int i = 0; i < NUMBER_IPv6; i++)
	{
		unsigned int dataRate = generate_dataRate(&mon_ipv6[i].packet_buf, (u64) INTERVAL_IN_S * 1000000000);    
		
		set_dataRate_ipv6(mon_ipv6[i].ip, dataRate, q->dataRate_ipv6);  
	}

	hrtimer_forward_now(&q->update_timer, ms_to_ktime(q->update_periode));
	return HRTIMER_RESTART;
}

static int
prio_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
    struct prio_sched_data *q = qdisc_priv(sch);
	unsigned int len = qdisc_pkt_len(skb);
	struct Qdisc *qdisc;
	int ret;
	int class;

    class = get_dataRate_class(skb, sch);
	qdisc = q->queues[class];

	ret = qdisc_enqueue(skb, qdisc, to_free);
	if (ret == NET_XMIT_SUCCESS) {
		sch->qstats.backlog += len;
		sch->q.qlen++;
		return NET_XMIT_SUCCESS;
	}
	if (net_xmit_drop_count(ret))
		qdisc_qstats_drop(sch);
	return ret;
}

static struct sk_buff *prio_peek(struct Qdisc *sch)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	int prio;

	for (prio = 0; prio < q->bands; prio++) {
		struct Qdisc *qdisc = q->queues[prio];
		struct sk_buff *skb = qdisc->ops->peek(qdisc);
		if (skb)
			return skb;
	}
	return NULL;
}

void monitoring_pkt_ipv6(struct in6_addr ip, unsigned int size)
{
	for (int i = 0; i < NUMBER_IPv6; i++)
	{
		u64 time = ktime_get_ns();

		if (ipv6_addr_equal(&ip, &mon_ipv6[i].ip))
		{
			struct packet pkt = {size, time};
			spin_lock(&mon_lock_ipv6);
			add_packet(&mon_ipv6[i].packet_buf, pkt);
			spin_unlock(&mon_lock_ipv6);
			return;
		}
		if(ipv6_addr_any(&mon_ipv6[i].ip))
        {
			struct packet pkt = {size, time};
        	mon_ipv6[i].ip = ip;
			spin_lock(&mon_lock_ipv6);
			add_packet(&mon_ipv6[i].packet_buf, pkt);
			spin_unlock(&mon_lock_ipv6);
			return;
        }
    }        
}

void monitoring_pkt_ipv4(unsigned int ip, unsigned int size)
{
	for (int i = 0; i < NUMBER_IPv4; i++)
	{
		u64 time = ktime_get_ns();

		if (ip == mon_ipv4[i].ip)
		{
			struct packet pkt = {size, time};
			spin_lock(&mon_lock_ipv4);
			add_packet(&mon_ipv4[i].packet_buf, pkt);
			spin_unlock(&mon_lock_ipv4);
			return;
		}
		if(mon_ipv4[i].ip == 0)
		{
			struct packet pkt = {size, time};
			mon_ipv4[i].ip = ip;
			spin_lock(&mon_lock_ipv4);
			add_packet(&mon_ipv4[i].packet_buf, pkt);
			spin_unlock(&mon_lock_ipv4);
			return;
		}
	}        
}

static struct sk_buff *prio_dequeue(struct Qdisc *sch)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	int prio;

	for (prio = 0; prio < q->bands; prio++) {
		struct Qdisc *qdisc = q->queues[prio];
		struct sk_buff *skb = qdisc_dequeue_peeked(qdisc);
		
		if (skb) {
			qdisc_bstats_update(sch, skb);
			qdisc_qstats_backlog_dec(sch, skb);
			sch->q.qlen--;

			// Monitoring
			if (skb->protocol == htons(ETH_P_IPV6)) {
				struct ipv6hdr *ip_header = ipv6_hdr(skb);
				struct in6_addr src_ip = (struct in6_addr)ip_header->saddr;  
				
				monitoring_pkt_ipv6(src_ip, skb->len);
	
			} else if (skb->protocol == htons(ETH_P_IP)) {
				struct iphdr *ip_header = ip_hdr(skb);
				unsigned int src_ip = (unsigned int)ip_header->saddr;
	
				monitoring_pkt_ipv4(src_ip, skb->len);

			}
			return skb;
		}
	}
	return NULL;
}

static void
prio_reset(struct Qdisc *sch)
{
	int prio;
	struct prio_sched_data *q = qdisc_priv(sch);

	for (prio = 0; prio < q->bands; prio++)
		qdisc_reset(q->queues[prio]);
}

static void
prio_destroy(struct Qdisc *sch)
{
	int prio;
	struct prio_sched_data *q = qdisc_priv(sch);

	for (prio = 0; prio < q->bands; prio++)
		qdisc_put(q->queues[prio]);

    // Timer
	hrtimer_cancel(&q->update_timer);
}

// NUMBER_IPv6 and NUMBER_IPv4 should be at least 60
static void add_dummy_IPs(struct Qdisc *sch)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	
	// dummy IPv6
    struct in6_addr ipv6;
	ipv6.in6_u.u6_addr8[0] = 32;
	ipv6.in6_u.u6_addr8[1] = 1;
	ipv6.in6_u.u6_addr8[2] = 7;
	ipv6.in6_u.u6_addr8[3] = 192;
	ipv6.in6_u.u6_addr8[4] = 32;
	ipv6.in6_u.u6_addr8[5] = 21;
	ipv6.in6_u.u6_addr8[6] = 2;
	ipv6.in6_u.u6_addr8[7] = 22;
	ipv6.in6_u.u6_addr8[8] = 1;
	ipv6.in6_u.u6_addr8[9] = 1;
	ipv6.in6_u.u6_addr8[10] = 1;
	ipv6.in6_u.u6_addr8[11] = 1;
	ipv6.in6_u.u6_addr8[12] = 1;
	ipv6.in6_u.u6_addr8[13] = 15;
	ipv6.in6_u.u6_addr8[14] = 5;
	ipv6.in6_u.u6_addr8[15] = 18;
  
    printk(KERN_INFO "add 50 dummy IPv6\n");
	for(int i = 0; i < 50; i++)
	{
		q->dataRate_ipv6[i].ip = ipv6;
		q->dataRate_ipv6[i].dataRate = 0;

		mon_ipv6[i].ip = ipv6;
	}
        
    printk(KERN_INFO "add 50 dummy IPv4\n");
	for(int i = 0; i < 50; i++)
	{
		q->dataRate_ipv4[i].ip = 1;
		q->dataRate_ipv4[i].dataRate = 0;

		mon_ipv4[i].ip = 1;
	}
}

static int prio_tune(struct Qdisc *sch, struct nlattr *opt,
		     struct netlink_ext_ack *extack)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	struct Qdisc *queues[TCQ_PRIO_BANDS];
	int oldbands = q->bands, i;
	struct tc_prio_qopt *qopt;

	if (nla_len(opt) < sizeof(*qopt))
		return -EINVAL;
	qopt = nla_data(opt);
	
	// configuration for evaluation
	qopt->bands = 3;
	q->thresholds[0] = 12500;
	q->thresholds[1] = 125000;
	q->thresholds[2] = 125000000;
	
	
	if (qopt->bands > TCQ_PRIO_BANDS || qopt->bands < TCQ_MIN_PRIO_BANDS)
		return -EINVAL;

	for (i = 0; i <= TC_PRIO_MAX; i++) {
		if (qopt->priomap[i] >= qopt->bands)
			return -EINVAL;
	}

	/* Before commit, make sure we can allocate all new qdiscs */
	for (i = oldbands; i < qopt->bands; i++) {
		queues[i] = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops,
					      TC_H_MAKE(sch->handle, i + 1),
					      extack);
		if (!queues[i]) {
			while (i > oldbands)
				qdisc_put(queues[--i]);
			return -ENOMEM;
		}
	}

	sch_tree_lock(sch);
	q->bands = qopt->bands;

	for (i = q->bands; i < oldbands; i++)
		qdisc_tree_flush_backlog(q->queues[i]);

	for (i = oldbands; i < q->bands; i++) {
		q->queues[i] = queues[i];
		if (q->queues[i] != &noop_qdisc)
			qdisc_hash_add(q->queues[i], true);
	}

	sch_tree_unlock(sch);
	
	for (i = q->bands; i < oldbands; i++)
		qdisc_put(q->queues[i]);

	return 0;
}

static int prio_init(struct Qdisc *sch, struct nlattr *opt,
		     struct netlink_ext_ack *extack)
{
	struct prio_sched_data *q = qdisc_priv(sch);

	if (!opt)
		return -EINVAL;

	// Variables
	q->update_periode = UPDATE_PERIODE_IN_MS;

	// Timer
	hrtimer_init(&q->update_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	q->update_timer.function = update_dataRate;
	hrtimer_start(&q->update_timer, ms_to_ktime(q->update_periode), HRTIMER_MODE_REL);

	// initialize Spinlock monitoring 
	spin_lock_init(&mon_lock_ipv4);
	spin_lock_init(&mon_lock_ipv6);

	// initialize Monitoring data structures
	for (int i = 0; i < NUMBER_IPv4; i++)
	{
		struct packet *data_space = kmalloc(MONITORING_SIZE * sizeof(struct packet), GFP_KERNEL);
		mon_ipv4[i].packet_buf.buffer = data_space;
		mon_ipv4[i].packet_buf.head = 0;
		mon_ipv4[i].packet_buf.maxlen = MONITORING_SIZE;
    }
        
    for (int i = 0; i < NUMBER_IPv6; i++)
	{
		struct packet *data_space = kmalloc(MONITORING_SIZE * sizeof(struct packet), GFP_KERNEL);
		mon_ipv6[i].packet_buf.buffer = data_space;
		mon_ipv6[i].packet_buf.head = 0;
		mon_ipv6[i].packet_buf.maxlen = MONITORING_SIZE;
    }
        
    // only for evaluation performance
	// add_dummy_IPs(sch);
        
	return prio_tune(sch, opt, extack);
}

static int prio_dump_offload(struct Qdisc *sch)
{
	struct tc_prio_qopt_offload hw_stats = {
		.command = TC_PRIO_STATS,
		.handle = sch->handle,
		.parent = sch->parent,
		{
			.stats = {
				.bstats = &sch->bstats,
				.qstats = &sch->qstats,
			},
		},
	};

	return qdisc_offload_dump_helper(sch, TC_SETUP_QDISC_PRIO, &hw_stats);
}

static int prio_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_prio_qopt opt;
	int err;

	opt.bands = q->bands;

	err = prio_dump_offload(sch);
	if (err)
		goto nla_put_failure;

	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int prio_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		      struct Qdisc **old, struct netlink_ext_ack *extack)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	struct tc_prio_qopt_offload graft_offload;
	unsigned long band = arg - 1;


	if (!new) {
		new = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops,
					TC_H_MAKE(sch->handle, arg), extack);
		if (!new)
			new = &noop_qdisc;
		else
			qdisc_hash_add(new, true);
	}

	*old = qdisc_replace(sch, new, &q->queues[band]);

	graft_offload.handle = sch->handle;
	graft_offload.parent = sch->parent;
	graft_offload.graft_params.band = band;
	graft_offload.graft_params.child_handle = new->handle;
	graft_offload.command = TC_PRIO_GRAFT;

	qdisc_offload_graft_helper(qdisc_dev(sch), sch, new, *old,
				   TC_SETUP_QDISC_PRIO, &graft_offload,
				   extack);
	return 0;
}

static struct Qdisc *
prio_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;

	return q->queues[band];
}

static unsigned long prio_find(struct Qdisc *sch, u32 classid)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	unsigned long band = TC_H_MIN(classid);

	if (band - 1 >= q->bands)
		return 0;
	return band;
}

static unsigned long prio_bind(struct Qdisc *sch, unsigned long parent, u32 classid)
{
	return prio_find(sch, classid);
}

static void prio_unbind(struct Qdisc *q, unsigned long cl)
{
}

static int prio_dump_class(struct Qdisc *sch, unsigned long cl, struct sk_buff *skb,
			   struct tcmsg *tcm)
{
	struct prio_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(cl);
	tcm->tcm_info = q->queues[cl-1]->handle;
	return 0;
}

static int prio_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				 struct gnet_dump *d)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	struct Qdisc *cl_q;

	cl_q = q->queues[cl - 1];
	if (gnet_stats_copy_basic(d, cl_q->cpu_bstats,
				  &cl_q->bstats, true) < 0 ||
	    qdisc_qstats_copy(d, cl_q) < 0)
		return -1;

	return 0;
}

static void prio_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	int prio;

	if (arg->stop)
		return;

	for (prio = 0; prio < q->bands; prio++) {
		if (!tc_qdisc_stats_dump(sch, prio + 1, arg))
			break;
	}
}

static const struct Qdisc_class_ops prio_class_ops = {
	.graft		=	prio_graft,
	.leaf		=	prio_leaf,
	.find		=	prio_find,
	.walk		=	prio_walk,
	.bind_tcf	=	prio_bind,
	.unbind_tcf	=	prio_unbind,
	.dump		=	prio_dump_class,
	.dump_stats	=	prio_dump_class_stats,
};

static struct Qdisc_ops ud_qos_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.cl_ops		=	&prio_class_ops,
	.id		=	"ud_qos",
	.priv_size	=	sizeof(struct prio_sched_data),
	.enqueue	=	prio_enqueue,
	.dequeue	=	prio_dequeue,
	.peek		=	prio_peek,
	.init		=	prio_init,
	.reset		=	prio_reset,
	.destroy	=	prio_destroy,
	.change		=	prio_tune,
	.dump		=	prio_dump,
	.owner		=	THIS_MODULE,
};

static int __init prio_module_init(void)
{
    printk(KERN_INFO "Load ud-qos\n");
	return register_qdisc(&ud_qos_qdisc_ops);
}

static void __exit prio_module_exit(void)
{
    printk(KERN_INFO "Exit ud-qos\n");
	unregister_qdisc(&ud_qos_qdisc_ops);
}

module_init(prio_module_init)
module_exit(prio_module_exit)

MODULE_LICENSE("GPL");
