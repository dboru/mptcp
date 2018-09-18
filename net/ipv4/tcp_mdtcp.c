/* DataCenter TCP (mdtcp_dctcp) congestion control.
 *
 * http://simula.stanford.edu/~alizade/Site/mdtcp_dctcp.html
 *
 * This is an implementation of mdtcp_dctcp over Reno, an enhancement to the
 * TCP congestion control algorithm designed for data centers. mdtcp_dctcp
 * leverages Explicit Congestion Notification (ECN) in the network to
 * provide multi-bit feedback to the end hosts. mdtcp_dctcp's goal is to meet
 * the following three data center transport requirements:
 *
 *  - High burst tolerance (incast due to partition/aggregate)
 *  - Low latency (short flows, queries)
 *  - High throughput (continuous data updates, large file transfers)
 *    with commodity shallow buffered switches
 *
 * The algorithm is described in detail in the following two papers:
 *
 * 1) Mohammad Alizadeh, Albert Greenberg, David A. Maltz, Jitendra Padhye,
 *    Parveen Patel, Balaji Prabhakar, Sudipta Sengupta, and Murari Sridharan:
 *      "Data Center TCP (mdtcp_dctcp)", Data Center Networks session
 *      Proc. ACM SIGCOMM, New Delhi, 2010.
 *   http://simula.stanford.edu/~alizade/Site/mdtcp_dctcp_files/mdtcp_dctcp-final.pdf
 *
 * 2) Mohammad Alizadeh, Adel Javanmard, and Balaji Prabhakar:
 *      "Analysis of mdtcp_dctcp: Stability, Convergence, and Fairness"
 *      Proc. ACM SIGMETRICS, San Jose, 2011.
 *   http://simula.stanford.edu/~alizade/Site/mdtcp_dctcp_files/mdtcp_dctcp_analysis-full.pdf
 *
 * Initial prototype from Abdul Kabbani, Masato Yasuda and Mohammad Alizadeh.
 *
 * Authors:
 *
 *	Daniel Borkmann <dborkman@redhat.com>
 *	Florian Westphal <fw@strlen.de>
 *	Glenn Judd <glenn.judd@morganstanley.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
// #include <linux/inet_diag.h>

#define MDTCP_DCTCP_MAX_ALPHA	1024U
#define mdtcp_dctcp_clamp_alpha_on_loss 0
#define mdtcp_dctcp_shift_g 4U
#define mdtcp_dctcp_alpha_on_init 1024U

// struct mdtcp_dctcp {
// 	u32 acked_bytes_ecn;
// 	u32 acked_bytes_total;
// 	u32 prior_snd_una;
// 	u32 prior_rcv_nxt;
// 	u32 mdtcp_dctcp_alpha;
// 	u32 next_seq;
// 	u32 ce_state;
// 	u32 delayed_ack_reserved;
// 	u32 loss_cwnd;
// };

// static unsigned int mdtcp_dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
// module_param(mdtcp_dctcp_shift_g, uint, 0644);
// MODULE_PARM_DESC(mdtcp_dctcp_shift_g, "parameter g for updating mdtcp_dctcp_alpha");

// static unsigned int mdtcp_dctcp_alpha_on_init __read_mostly =MDTCP_DCTCP_MAX_ALPHA;
// module_param(mdtcp_dctcp_alpha_on_init, uint, 0644);
// MODULE_PARM_DESC(mdtcp_dctcp_alpha_on_init, "parameter for initial alpha value");

// static unsigned int mdtcp_dctcp_clamp_alpha_on_loss __read_mostly;
// module_param(mdtcp_dctcp_clamp_alpha_on_loss, uint, 0644);
// MODULE_PARM_DESC(mdtcp_dctcp_clamp_alpha_on_loss,
// 		 "parameter for clamping alpha on loss");

// static struct tcp_congestion_ops mdtcp_dctcp_reno;

static void mdtcp_dctcp_reset(struct tcp_sock *tp)
{
	tp->next_seq = tp->snd_nxt;

	tp->acked_bytes_ecn = 0;
	tp->acked_bytes_total = 0;
}

void mdtcp_dctcp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if ((tp->ecn_flags & TCP_ECN_OK) ||
	    (sk->sk_state == TCP_LISTEN ||
	     sk->sk_state == TCP_CLOSE)) {
		tp->prior_snd_una = tp->snd_una;
		tp->prior_rcv_nxt = tp->rcv_nxt;

		tp->mdtcp_dctcp_alpha = min(mdtcp_dctcp_alpha_on_init, MDTCP_DCTCP_MAX_ALPHA);

		tp->delayed_ack_reserved = 0;
		tp->loss_cwnd = 0;
		tp->ce_state = 0;

		mdtcp_dctcp_reset(tp);
		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for mdtcp_dctcp.
	 */
	inet_csk(sk)->icsk_ca_ops = &tcp_reno;
	INET_ECN_dontxmit(sk);
}
EXPORT_SYMBOL_GPL(mdtcp_dctcp_init);

u32 mdtcp_dctcp_ssthresh(struct sock *sk)
{      // struct inet_sock *inet=inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	tp->loss_cwnd = tp->snd_cwnd;
       //printk("dc-alpha:cwnd %u dc-alpha %u ssthresh %u destip %pI4/%u \n",
        //tp->snd_cwnd,tp->mdtcp_dctcp_alpha,max(tp->snd_cwnd - ((tp->snd_cwnd * tp->mdtcp_dctcp_alpha) >> 11U), 2U),&inet->inet_daddr,
         //ntohs(inet->inet_dport));


	return max(tp->snd_cwnd - ((tp->snd_cwnd * tp->mdtcp_dctcp_alpha) >> 11U), 2U);
}
EXPORT_SYMBOL_GPL(mdtcp_dctcp_ssthresh);

/* Minimal DCTP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */

static void mdtcp_dctcp_ce_state_0_to_1(struct sock *sk)
{
	
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=0 to CE=1 and delayed
	 * ACK has not sent yet.
	 */
	if (!tp->ce_state && tp->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=0. */
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = tp->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	tp->prior_rcv_nxt = tp->rcv_nxt;
	tp->ce_state = 1;

	tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
}

static void mdtcp_dctcp_ce_state_1_to_0(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=1 to CE=0 and delayed
	 * ACK has not sent yet.
	 */
	if (tp->ce_state && tp->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=1. */
		tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = tp->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	tp->prior_rcv_nxt = tp->rcv_nxt;
	tp->ce_state = 0;

	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

// static void mdtcp_dctcp_update_alpha(struct sock *sk, u32 flags)
void mdtcp_dctcp_update_alpha(struct sock *sk, u32 flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
       // struct inet_sock *inet=inet_sk(sk);
	u32 acked_bytes = tp->snd_una - tp->prior_snd_una;

	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = inet_csk(sk)->icsk_ack.rcv_mss;
	if (acked_bytes) {
		tp->acked_bytes_total += acked_bytes;
		tp->prior_snd_una = tp->snd_una;

		if (flags & CA_ACK_ECE)
			tp->acked_bytes_ecn += acked_bytes;
	}

	/* Expired RTT */
	if (!before(tp->snd_una, tp->next_seq)) {
		u64 bytes_ecn = tp->acked_bytes_ecn;
		u32 alpha = tp->mdtcp_dctcp_alpha;

		/* alpha = (1 - g) * alpha + g * F */

		alpha -= min_not_zero(alpha, alpha >> mdtcp_dctcp_shift_g);
		if (bytes_ecn) {
			/* If mdtcp_dctcp_shift_g == 1, a 32bit value would overflow
			 * after 8 Mbytes.
			 */
			bytes_ecn <<= (10 - mdtcp_dctcp_shift_g);
			do_div(bytes_ecn, max(1U, tp->acked_bytes_total));

			alpha = min(alpha + (u32)bytes_ecn, MDTCP_DCTCP_MAX_ALPHA);
		}
		/* mdtcp_dctcp_alpha can be read from mdtcp_dctcp_get_info() without
		 * synchro, so we ask compiler to not use mdtcp_dctcp_alpha
		 * as a temporary variable in prior operations.
		 */
		WRITE_ONCE(tp->mdtcp_dctcp_alpha, alpha);
		mdtcp_dctcp_reset(tp);
	}

  
}
EXPORT_SYMBOL_GPL(mdtcp_dctcp_update_alpha);

void mdtcp_dctcp_state(struct sock *sk, u8 new_state)
{
	if (mdtcp_dctcp_clamp_alpha_on_loss && new_state == TCP_CA_Loss) {
		// struct mdtcp_dctcp *ca = inet_csk_ca(sk);
		struct tcp_sock *tp = tcp_sk(sk);

		/* If this extension is enabled, we clamp mdtcp_dctcp_alpha to
		 * max on packet loss; the motivation is that mdtcp_dctcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 */
		tp->mdtcp_dctcp_alpha = MDTCP_DCTCP_MAX_ALPHA;
	}
}
EXPORT_SYMBOL_GPL(mdtcp_dctcp_state);

static void mdtcp_dctcp_update_ack_reserved(struct sock *sk, enum tcp_ca_event ev)
{
	// struct mdtcp_dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);


	switch (ev) {
	case CA_EVENT_DELAYED_ACK:
		if (!tp->delayed_ack_reserved)
			tp->delayed_ack_reserved = 1;
		break;
	case CA_EVENT_NON_DELAYED_ACK:
		if (tp->delayed_ack_reserved)
			tp->delayed_ack_reserved = 0;
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}


void mdtcp_dctcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	switch (ev) {
	case CA_EVENT_ECN_IS_CE:
		mdtcp_dctcp_ce_state_0_to_1(sk);
		break;
	case CA_EVENT_ECN_NO_CE:
		mdtcp_dctcp_ce_state_1_to_0(sk);
		break;
	case CA_EVENT_DELAYED_ACK:
	case CA_EVENT_NON_DELAYED_ACK:
		mdtcp_dctcp_update_ack_reserved(sk, ev);
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

EXPORT_SYMBOL_GPL(mdtcp_dctcp_cwnd_event);

u32 mdtcp_dctcp_cwnd_undo(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	return max(tcp_sk(sk)->snd_cwnd, tp->loss_cwnd);
}
EXPORT_SYMBOL_GPL(mdtcp_dctcp_cwnd_undo);
