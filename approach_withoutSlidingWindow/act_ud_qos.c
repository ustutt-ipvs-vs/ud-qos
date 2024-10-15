// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/act_ud_qos.c	Usage-Dependent Quality of Service 
 *
 * based on: 	net/sched/act_simple.c
 *
 * Authors:	Jona Herrmann
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/tc_wrapper.h>

#include <linux/tc_act/tc_defact.h>
#include <net/tc_act/tc_defact.h>
//////////////
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>

// Parameters
#define NUMBER_CLASSES 3
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

// Variables for Monitoring 
spinlock_t mon_lock_ipv4;
spinlock_t mon_lock_ipv6;
struct monitoring_ipv4 mon_ipv4[NUMBER_IPv4];
struct monitoring_ipv6 mon_ipv6[NUMBER_IPv6];

static struct tc_action_ops act_ud_qos_ops;

struct ud_qos {
	struct hrtimer update_timer;
	u64 update_periode;
	struct dataRate_node_ipv4 dataRate_ipv4[NUMBER_IPv4];
	struct dataRate_node_ipv6 dataRate_ipv6[NUMBER_IPv6];
	unsigned int thresholds[NUMBER_CLASSES];
	unsigned int dropProbability[NUMBER_CLASSES];
};

struct ud_qos ud_qos;

// for evaluation drop rates
struct dropping_ipv4 {
	unsigned int ip;
	unsigned int total_pkt;
	unsigned int drop_pkt;
};
struct dropping_ipv6 {
	struct in6_addr ip;
	unsigned int total_pkt;
	unsigned int drop_pkt;
};

struct dropping_ipv4 drop_ipv4[2];
struct dropping_ipv6 drop_ipv6[2];
/////////////////////////////////////////


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

static unsigned int get_dataRate_ipv6(struct in6_addr ip, struct dataRate_node_ipv6 dataRate[NUMBER_IPv6])
{
	for(int i = 0; i < NUMBER_IPv6; i++)
	{
		if(ipv6_addr_equal(&ip, &dataRate[i].ip))
		{
			return dataRate[i].dataRate;
		}
	}

	return 0;
}

static unsigned int get_dataRate_ipv4(unsigned int ip, struct dataRate_node_ipv4 dataRate[NUMBER_IPv4])
{
	for(int i = 0; i < NUMBER_IPv4; i++)
	{
		if(dataRate[i].ip == ip)
		{
			return dataRate[i].dataRate;
		}
	}

	return 0;
}

static u32 get_loss_ipv6(struct in6_addr ip)
{
	int prio;
	unsigned int dataRate = get_dataRate_ipv6(ip, ud_qos.dataRate_ipv6);

	for (prio = 0; prio < NUMBER_CLASSES; prio++) {
		if (dataRate < ud_qos.thresholds[prio])
		{
	    	return ud_qos.dropProbability[prio];
		}
	}
	
	return ud_qos.dropProbability[NUMBER_CLASSES - 1];
}

static u32 get_loss_ipv4(unsigned int ip)
{
	int prio;
	unsigned int dataRate = get_dataRate_ipv4(ip, ud_qos.dataRate_ipv4);

	for (prio = 0; prio < NUMBER_CLASSES; prio++) {
		if (dataRate < ud_qos.thresholds[prio])
		{
	    	return ud_qos.dropProbability[prio];
		}
	}
	
	return ud_qos.dropProbability[NUMBER_CLASSES - 1];
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

static enum hrtimer_restart update_dataRate(struct hrtimer *timer)
{
	for(int i = 0; i < NUMBER_IPv4; i++)
	{
		unsigned int dataRate = generate_dataRate(&mon_ipv4[i].packet_buf, (u64) INTERVAL_IN_S * 1000000000);    
		
		set_dataRate_ipv4(mon_ipv4[i].ip, dataRate, ud_qos.dataRate_ipv4);
	}
	
	for(int i = 0; i < NUMBER_IPv6; i++)
	{
		unsigned int dataRate = generate_dataRate(&mon_ipv6[i].packet_buf, (u64) INTERVAL_IN_S * 1000000000);    
		
		set_dataRate_ipv6(mon_ipv6[i].ip, dataRate, ud_qos.dataRate_ipv6);  
	}

	hrtimer_forward_now(&ud_qos.update_timer, ms_to_ktime(ud_qos.update_periode));
	return HRTIMER_RESTART;
}

#define SIMP_MAX_DATA	32
TC_INDIRECT_SCOPE int tcf_simp_act(struct sk_buff *skb,
				   const struct tc_action *a,
				   struct tcf_result *res)
{
	struct tcf_defact *d = to_defact(a);
	struct ipv6hdr *ipv6_header;
	struct iphdr *ipv4_header;
	u32 dropProbability = 0;
	unsigned int pkt_len;

	spin_lock(&d->tcf_lock);
	tcf_lastuse_update(&d->tcf_tm);
	bstats_update(&d->tcf_bstats, skb); 

	if (skb->protocol == htons(ETH_P_IPV6)) {
		ipv6_header = ipv6_hdr(skb);
		struct in6_addr dest_ip = (struct in6_addr)ipv6_header->daddr;
		                 
		// get dropProbability from qdisc for ip
		dropProbability = get_loss_ipv6(dest_ip);
                
        /* Drop packet? */
		if (dropProbability && dropProbability >= get_random_u32()) {
			// for evaluation drop rates
			/*
			if (ipv6_addr_equal(&drop_ipv6[0].ip, &dest_ip)) {
				drop_ipv6[0].total_pkt = drop_ipv6[0].total_pkt + 1;
				drop_ipv6[0].drop_pkt = drop_ipv6[0].drop_pkt + 1;
			}
			else if (ipv6_addr_equal(&drop_ipv6[1].ip, &dest_ip)) {
				drop_ipv6[1].total_pkt = drop_ipv6[1].total_pkt + 1;
				drop_ipv6[1].drop_pkt = drop_ipv6[1].drop_pkt + 1;
			}
			*/
			
			spin_unlock(&d->tcf_lock);
			return TC_ACT_SHOT;
		}
		
		// for evaluation drop rates
		/*
		if (ipv6_addr_equal(&drop_ipv6[0].ip, &dest_ip)) {
			drop_ipv6[0].total_pkt = drop_ipv6[0].total_pkt + 1;
		}
		else if (ipv6_addr_equal(&drop_ipv6[1].ip, &dest_ip)) {
			drop_ipv6[1].total_pkt = drop_ipv6[1].total_pkt + 1;
		}
		*/
	
		// + 14 because ethernet header len not included in skb->len
		pkt_len = skb->len + 14;
			
		monitoring_pkt_ipv6(dest_ip, pkt_len);
	}
	else if (skb->protocol == htons(ETH_P_IP)) {
		ipv4_header = ip_hdr(skb);
		unsigned int dest_ip = (unsigned int)ipv4_header->daddr;
                
		// get dropProbability from qdisc for ip
		dropProbability = get_loss_ipv4(dest_ip);
	  
		/* Drop packet? */
		if (dropProbability && dropProbability >= get_random_u32()) {
			// for evaluation drop rates
			/*
			if (drop_ipv4[0].ip == dest_ip) {
				drop_ipv4[0].total_pkt = drop_ipv4[0].total_pkt + 1;
				drop_ipv4[0].drop_pkt = drop_ipv4[0].drop_pkt + 1;
			}
			else if (drop_ipv4[1].ip == dest_ip) {
				drop_ipv4[1].total_pkt = drop_ipv4[1].total_pkt + 1;
				drop_ipv4[1].drop_pkt = drop_ipv4[1].drop_pkt + 1;
			}
			*/
			
			spin_unlock(&d->tcf_lock);
			return TC_ACT_SHOT;
		}
		
		// for evaluation drop rates
		/*
		if (drop_ipv4[0].ip == dest_ip) {
            drop_ipv4[0].total_pkt = drop_ipv4[0].total_pkt + 1;
		}
	    else if (drop_ipv4[1].ip == dest_ip) {
		    drop_ipv4[1].total_pkt = drop_ipv4[1].total_pkt + 1;
		}
		*/
			
		// + 14 because ethernet header len not included in skb->len
		pkt_len = skb->len + 14;
			
		monitoring_pkt_ipv4(dest_ip, pkt_len);
	}

	spin_unlock(&d->tcf_lock);
	return d->tcf_action;
}

static void tcf_simp_release(struct tc_action *a)
{
	struct tcf_defact *d = to_defact(a);
	kfree(d->tcfd_defdata);
	
	// Timer
	hrtimer_cancel(&ud_qos.update_timer);
}

static int alloc_defdata(struct tcf_defact *d, const struct nlattr *defdata)
{
	d->tcfd_defdata = kzalloc(SIMP_MAX_DATA, GFP_KERNEL);
	if (unlikely(!d->tcfd_defdata))
		return -ENOMEM;
	nla_strscpy(d->tcfd_defdata, defdata, SIMP_MAX_DATA);
	return 0;
}

static int reset_policy(struct tc_action *a, const struct nlattr *defdata,
			struct tc_defact *p, struct tcf_proto *tp,
			struct netlink_ext_ack *extack)
{
	struct tcf_chain *goto_ch = NULL;
	struct tcf_defact *d;
	int err;

	err = tcf_action_check_ctrlact(p->action, tp, &goto_ch, extack);
	if (err < 0)
		return err;
	d = to_defact(a);
	spin_lock_bh(&d->tcf_lock);
	goto_ch = tcf_action_set_ctrlact(a, p->action, goto_ch);
	memset(d->tcfd_defdata, 0, SIMP_MAX_DATA);
	nla_strscpy(d->tcfd_defdata, defdata, SIMP_MAX_DATA);
	spin_unlock_bh(&d->tcf_lock);
	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);
	return 0;
}

static const struct nla_policy simple_policy[TCA_DEF_MAX + 1] = {
	[TCA_DEF_PARMS]	= { .len = sizeof(struct tc_defact) },
	[TCA_DEF_DATA]	= { .type = NLA_STRING, .len = SIMP_MAX_DATA },
};

static int tcf_simp_init(struct net *net, struct nlattr *nla,
			 struct nlattr *est, struct tc_action **a,
			 struct tcf_proto *tp, u32 flags,
			 struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, act_ud_qos_ops.net_id);
	bool bind = flags & TCA_ACT_FLAGS_BIND;
	struct nlattr *tb[TCA_DEF_MAX + 1];
	struct tcf_chain *goto_ch = NULL;
	struct tc_defact *parm;
	struct tcf_defact *d;
	bool exists = false;
	int ret = 0, err;
	u32 index;

	if (nla == NULL)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_DEF_MAX, nla, simple_policy,
					  NULL);
	if (err < 0)
		return err;

	if (tb[TCA_DEF_PARMS] == NULL)
		return -EINVAL;
	
	// Variables
	ud_qos.update_periode = UPDATE_PERIODE_IN_MS;
	
	// configuration for evaluation
    ud_qos.thresholds[0] = 250000;
	ud_qos.thresholds[1] = 3750000;
	ud_qos.thresholds[2] = 125000000;
	ud_qos.dropProbability[0] = 0; 	     // 0%
	ud_qos.dropProbability[1] = 2147484; // 0.05%
	ud_qos.dropProbability[2] = 4294967; // 0.1%

	// Timer
	hrtimer_init(&ud_qos.update_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	ud_qos.update_timer.function = update_dataRate;
	hrtimer_start(&ud_qos.update_timer, ms_to_ktime(ud_qos.update_periode), HRTIMER_MODE_REL);

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


	// only for evaluation drop rates
	// set corresponding IPs
	/*
    /////////////////////////////////////////////////
	drop_ipv4[0].ip = 0;
	drop_ipv4[1].ip = 0;
    /////////////////////////////////////////////////
	struct in6_addr ipv6_0;
	struct in6_addr ipv6_1;
	ipv6_0.in6_u.u6_addr8[0] = 0;
	ipv6_0.in6_u.u6_addr8[1] = 0;
	ipv6_0.in6_u.u6_addr8[2] = 0;
	ipv6_0.in6_u.u6_addr8[3] = 0;
	ipv6_0.in6_u.u6_addr8[4] = 0;
	ipv6_0.in6_u.u6_addr8[5] = 0;
	ipv6_0.in6_u.u6_addr8[6] = 0;
	ipv6_0.in6_u.u6_addr8[7] = 0;
	ipv6_0.in6_u.u6_addr8[8] = 0;
	ipv6_0.in6_u.u6_addr8[9] = 0;
	ipv6_0.in6_u.u6_addr8[10] = 0;
	ipv6_0.in6_u.u6_addr8[11] = 0;
	ipv6_0.in6_u.u6_addr8[12] = 0;
	ipv6_0.in6_u.u6_addr8[13] = 0;
	ipv6_0.in6_u.u6_addr8[14] = 0;
	ipv6_0.in6_u.u6_addr8[15] = 0;
	
	ipv6_1.in6_u.u6_addr8[0] = 0;
	ipv6_1.in6_u.u6_addr8[1] = 0;
	ipv6_1.in6_u.u6_addr8[2] = 0;
	ipv6_1.in6_u.u6_addr8[3] = 0;
	ipv6_1.in6_u.u6_addr8[4] = 0;
	ipv6_1.in6_u.u6_addr8[5] = 0;
	ipv6_1.in6_u.u6_addr8[6] = 0;
	ipv6_1.in6_u.u6_addr8[7] = 0;
	ipv6_1.in6_u.u6_addr8[8] = 0;
	ipv6_1.in6_u.u6_addr8[9] = 0;
	ipv6_1.in6_u.u6_addr8[10] = 0;
	ipv6_1.in6_u.u6_addr8[11] = 0;
	ipv6_1.in6_u.u6_addr8[12] = 0;
	ipv6_1.in6_u.u6_addr8[13] = 0;
	ipv6_1.in6_u.u6_addr8[14] = 0;
	ipv6_1.in6_u.u6_addr8[15] = 0;
	
	drop_ipv6[0].ip = ipv6_0;
	drop_ipv6[1].ip = ipv6_1;
	*/
	////////////////////////////////////////////////////////
	

	parm = nla_data(tb[TCA_DEF_PARMS]);
	index = parm->index;
	err = tcf_idr_check_alloc(tn, &index, a, bind);
	if (err < 0)
		return err;
	exists = err;
	if (exists && bind)
		return 0;

	if (tb[TCA_DEF_DATA] == NULL) {
		if (exists)
			tcf_idr_release(*a, bind);
		else
			tcf_idr_cleanup(tn, index);
		return -EINVAL;
	}

	if (!exists) {
		ret = tcf_idr_create(tn, index, est, a,
				     &act_ud_qos_ops, bind, false, flags);
		if (ret) {
			tcf_idr_cleanup(tn, index);
			return ret;
		}

		d = to_defact(*a);
		err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch,
					       extack);
		if (err < 0)
			goto release_idr;

		err = alloc_defdata(d, tb[TCA_DEF_DATA]);
		if (err < 0)
			goto put_chain;

		tcf_action_set_ctrlact(*a, parm->action, goto_ch);
		ret = ACT_P_CREATED;
	} else {
		if (!(flags & TCA_ACT_FLAGS_REPLACE)) {
			err = -EEXIST;
			goto release_idr;
		}

		err = reset_policy(*a, tb[TCA_DEF_DATA], parm, tp, extack);
		if (err)
			goto release_idr;
	}

	return ret;
put_chain:
	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);
release_idr:
	tcf_idr_release(*a, bind);
	return err;
}

static int tcf_simp_dump(struct sk_buff *skb, struct tc_action *a,
			 int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_defact *d = to_defact(a);
	struct tc_defact opt = {
		.index   = d->tcf_index,
		.refcnt  = refcount_read(&d->tcf_refcnt) - ref,
		.bindcnt = atomic_read(&d->tcf_bindcnt) - bind,
	};
	struct tcf_t t;

	spin_lock_bh(&d->tcf_lock);
	opt.action = d->tcf_action;
	if (nla_put(skb, TCA_DEF_PARMS, sizeof(opt), &opt) ||
	    nla_put_string(skb, TCA_DEF_DATA, d->tcfd_defdata))
		goto nla_put_failure;

	tcf_tm_dump(&t, &d->tcf_tm);
	if (nla_put_64bit(skb, TCA_DEF_TM, sizeof(t), &t, TCA_DEF_PAD))
		goto nla_put_failure;
	spin_unlock_bh(&d->tcf_lock);

	return skb->len;

nla_put_failure:
	spin_unlock_bh(&d->tcf_lock);
	nlmsg_trim(skb, b);
	return -1;
}

static struct tc_action_ops act_ud_qos_ops = {
	.kind		=	"ud_qos",
	.id			=	TCA_ID_SIMP,
	.owner		=	THIS_MODULE,
	.act		=	tcf_simp_act,
	.dump		=	tcf_simp_dump,
	.cleanup	=	tcf_simp_release,
	.init		=	tcf_simp_init,
	.size		=	sizeof(struct tcf_defact),
};

static __net_init int simp_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, act_ud_qos_ops.net_id);

	return tc_action_net_init(net, tn, &act_ud_qos_ops);
}

static void __net_exit simp_exit_net(struct list_head *net_list)
{
	tc_action_net_exit(net_list, act_ud_qos_ops.net_id);
}

static struct pernet_operations mon_net_ops = {
	.init = simp_init_net,
	.exit_batch = simp_exit_net,
	.id   = &act_ud_qos_ops.net_id,
	.size = sizeof(struct tc_action_net),
};

MODULE_DESCRIPTION("Ud-qos action");
MODULE_LICENSE("GPL");

static int __init simp_init_module(void)
{
	int ret = tcf_register_action(&act_ud_qos_ops, &mon_net_ops);
	if (!ret)
		pr_info("Ud-qos action Loaded\n");
	return ret;
}

static void __exit simp_cleanup_module(void)
{
	// for evaluation drop rates
	/*
	unsigned int drop_rate = 0;
	if (drop_ipv4[0].total_pkt > 0) 
	{
		drop_rate = (drop_ipv4[0].drop_pkt * 100 * 1000)/drop_ipv4[0].total_pkt;
		printk(KERN_INFO "%pI4 - %u * 10e-3 %%\n", &ipv4_0, drop_rate);
	}
	if (drop_ipv4[1].total_pkt > 0) 
    {
		drop_rate = (drop_ipv4[1].drop_pkt * 100 * 1000)/drop_ipv4[1].total_pkt;
		printk(KERN_INFO "%pI4 - %u * 10e-3 %%\n", &ipv4_1, drop_rate);
	}
	
	if (drop_ipv6[0].total_pkt > 0) 
    {
		drop_rate = (drop_ipv6[0].drop_pkt * 100 * 1000)/drop_ipv6[0].total_pkt;
		printk(KERN_INFO "%pI6c - %u * 10e-3 %%\n", &ipv6_0, drop_rate);
	}
	if (drop_ipv6[1].total_pkt > 0) 
    {
		drop_rate = (drop_ipv6[1].drop_pkt * 100 * 1000)/drop_ipv6[1].total_pkt;
		printk(KERN_INFO "%pI6c - %u * 10e-3 %%\n", &ipv6_1, drop_rate);
	}
	*/
	
	pr_info("Ud-qos action Exit\n");
	
	tcf_unregister_action(&act_ud_qos_ops, &mon_net_ops);
}

module_init(simp_init_module);
module_exit(simp_cleanup_module);
