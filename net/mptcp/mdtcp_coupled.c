/*
 *	 Multipath Datacenter TCP(MDTCP)-a Coupled Congestion Control for Datacenter
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer & Author:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Octavian Purdila <octavian.purdila@intel.com>
 *	John Ronan <jronan@tssg.org>
 *	Catalin Nicutar <catalin.nicutar@gmail.com>
 *	Brandon Heller <brandonh@stanford.edu>
 *      Dejene Boru Oljira <oljideje@kau.se>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <net/tcp.h>
#include <net/mptcp.h>

#include <linux/module.h>

#include <linux/mm.h>
#include <linux/ktime.h>
// #include <linux/inet_diag.h>


#define MDTCP_MAX_ALPHA	1024U

/* Scaling is done in the numerator with alpha_scale_num and in the denominator
 * with alpha_scale_den.
 *
 * To downscale, we just need to use alpha_scale.
 *
 * We have: alpha_scale = alpha_scale_num / (alpha_scale_den)
 */
//static int alpha_scale_den = 10;
//static int alpha_scale_num = 20;
// static int alpha_scale = 10;


static int alpha_scale_den = 10;
// static int alpha_scale_num = 20;

static int alpha_scale_num = 20;
static int alpha_scale = 10;



struct mdtcp {
	/*mptcp parameters*/
	u64	alpha;
	// u64 cwnd_sum;
	bool forced_update;

	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 mdtcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 delayed_ack_reserved;
	u32 loss_cwnd;
	ktime_t start;
	bool debug;
	

};

/*mdtcp specifics*/
static unsigned int mdtcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(mdtcp_shift_g, uint, 0644);
MODULE_PARM_DESC(mdtcp_shift_g, "parameter g for updating mdtcp_alpha");

static unsigned int mdtcp_alpha_on_init __read_mostly = MDTCP_MAX_ALPHA;
module_param(mdtcp_alpha_on_init, uint, 0644);
MODULE_PARM_DESC(mdtcp_alpha_on_init, "parameter for initial alpha value");

static unsigned int mdtcp_clamp_alpha_on_loss __read_mostly;
module_param(mdtcp_clamp_alpha_on_loss, uint, 0644);
MODULE_PARM_DESC(mdtcp_clamp_alpha_on_loss,
		"parameter for clamping alpha on loss");
static unsigned int mdtcp_enable_avg_alfa __read_mostly = 0; /* g = 1/2^4 */
module_param(mdtcp_enable_avg_alfa, uint, 0644);
MODULE_PARM_DESC(mdtcp_enable_avg_alfa, "parameter to enalbe use average congestion signals of subflows");

static unsigned int mdtcp_debug __read_mostly = 0; 
module_param(mdtcp_debug, uint, 0644);
MODULE_PARM_DESC(mdtcp_debug, "enable print log");

/*end mdtcp*/


// static struct tcp_congestion_ops mdtcp_reno;

static inline int mdtcp_sk_can_send(const struct sock *sk)
{
	return mptcp_sk_can_send(sk) && tcp_sk(sk)->srtt_us;
}

static inline u64 mdtcp_get_alpha(const struct sock *meta_sk)
{
	return ((struct mdtcp *)inet_csk_ca(meta_sk))->alpha;
}

static inline void mdtcp_set_alpha(const struct sock *meta_sk, u64 alpha)
{
	((struct mdtcp *)inet_csk_ca(meta_sk))->alpha = alpha;
}


// static inline void mdtcp_set_alfa_flag(const struct sock *meta_sk, bool value)
// {
// 	((struct mdtcp *)inet_csk_ca(meta_sk))->alfa_flag = value;
// }

// static inline bool mdtcp_get_alfa_flag(const struct sock *meta_sk)
// {
// 	return ((struct mdtcp *)inet_csk_ca(meta_sk))->alfa_flag;
// }

// static inline u32 mdtcp_get_max_dctcp_alfa(const struct sock *meta_sk)
// {
// 	return ((struct mdtcp *)inet_csk_ca(meta_sk))->mdtcp_max_dctcp_alfa;
// }

// static inline void mdtcp_set_max_dctcp_alfa(const struct sock *sk, u32 alfa)
// {


// 	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
// 	const struct sock *sub_sk;

// 	if (!mdtcp_get_alfa_flag(sk)) {
// 		((struct mdtcp *)inet_csk_ca(sk))->mdtcp_max_dctcp_alfa = alfa;
// 		mdtcp_set_alfa_flag(sk, 1);
// 		return;
// 	}

// 	if (mpcb && mpcb->cnt_established > 1) {
// 		u32 alfa_sum = 0;
// 		/* Calculate sum of cong_estimate */
// 		mptcp_for_each_sk(mpcb, sub_sk) {
// 			struct tcp_sock *sub_tp = tcp_sk(sub_sk);
// 			if (!mdtcp_sk_can_send(sub_sk))
// 				continue;
// 			alfa_sum += sub_tp->mdtcp_cong_estimate;
// 			// if (sub_tp->mdtcp_cong_estimate < alfa_sum)
// 			// 	alfa_sum = sub_tp->mdtcp_cong_estimate;
// 			// printk(" alfa_sum : %u \n", alfa_sum);
// 		}
// 		// if (alfa_sum > 0 ) {
// 			alfa_sum = alfa_sum / mpcb->cnt_established;

// 			// printk("after div alfa_sum : %u\n", alfa_sum);
// 			((struct mdtcp *)inet_csk_ca(sk))->mdtcp_max_dctcp_alfa = alfa_sum;
// 		// }


// 	}


// }


// static inline u64 mdtcp_get_cwnd_total(const struct sock *meta_sk)
// {
// 	return ((struct mdtcp *)inet_csk_ca(meta_sk))->cwnd_sum;
// }

// static inline void mdtcp_set_cwnd_total(const struct sock *meta_sk, u64 tot_cwnd)
// {
// 	((struct mdtcp *)inet_csk_ca(meta_sk))->cwnd_sum = tot_cwnd;
// }

static inline u64 mdtcp_scale(u32 val, int scale)
{
	return (u64) val << scale;
}

static inline bool mdtcp_get_forced(const struct sock *meta_sk)
{
	return ((struct mdtcp *)inet_csk_ca(meta_sk))->forced_update;
}

static void mdtcp_reset(const struct tcp_sock *tp, struct mdtcp *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
}


static u32 mdtcp_ssthresh(struct sock *sk)
{
	struct mdtcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	const struct sock *sub_sk;

	// struct inet_sock *inet = inet_sk(sk);
	// struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), ca->start));


	ca->loss_cwnd = tp->snd_cwnd;

	// if (ntohs(inet->inet_sport) != 5001) {
	// 	printk("ktime: %lu.%09lu cwnd: %u dctcp-alfa: %u srcip %pI4/%u dstip %pI4/%u rtt: %u ssthresh %u\n",
	// 	       (unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec, tp->snd_cwnd, ca->mdtcp_alpha, &inet->inet_saddr,
	// 	       ntohs(inet->inet_sport), &inet->inet_daddr,
	// 	       ntohs(inet->inet_dport), tp->srtt_us >> 3, max(tp->snd_cwnd - ((tp->snd_cwnd * ca->mdtcp_alpha) >> 11U), 2U));
	// }

	// if (mpcb && mpcb->cnt_established > 1) {
	// 	// u32 max_alfa = mdtcp_get_max_dctcp_alfa(sk);

	// 	// mdtcp_set_max_dctcp_alfa(mptcp_meta_sk(sk), ca->mdtcp_alpha);

	// 	// return max(tp->snd_cwnd - ((tp->snd_cwnd * max_alfa) >> 11U), 2U);
	// 	return max(tp->snd_cwnd - ((6*tp->snd_cwnd * ca->mdtcp_alpha/5) >> 11U), 2U);
	// }

	if (mdtcp_enable_avg_alfa && mpcb && mpcb->cnt_established>1) {
		u32 alfa_mean=0;
		/* Calculate the alfa mean */
		mptcp_for_each_sk(mpcb, sub_sk) {
			struct tcp_sock *sub_tp = tcp_sk(sub_sk);
			if (!mdtcp_sk_can_send(sub_sk))
				continue;
			alfa_mean += sub_tp->mdtcp_cong_estimate;
		}
		alfa_mean=alfa_mean/mpcb->cnt_established;

		return max(tp->snd_cwnd - ((tp->snd_cwnd * alfa_mean) >> 11U), 2U);


	}


	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->mdtcp_alpha) >> 11U), 2U);
}

/* Minimal DCTP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */

static void mdtcp_ce_state_0_to_1(struct sock *sk)
{
	struct mdtcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=0 to CE=1 and delayed
	 * ACK has not sent yet.
	 */
	if (!ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=0. */
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 1;

	tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
}

static void mdtcp_ce_state_1_to_0(struct sock *sk)
{
	struct mdtcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=1 to CE=0 and delayed
	 * ACK has not sent yet.
	 */
	if (ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=1. */
		tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 0;

	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}



static void mdtcp_update_alpha(struct sock *sk, u32 flags)

{

	struct tcp_sock *tp = tcp_sk(sk);
	struct mdtcp *ca = inet_csk_ca(sk);
	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;
	struct inet_sock *inet = inet_sk(sk);
	struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), ca->start));
	// const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;

	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = inet_csk(sk)->icsk_ack.rcv_mss;
	if (acked_bytes) {
		ca->acked_bytes_total += acked_bytes;
		ca->prior_snd_una = tp->snd_una;
		if (flags & CA_ACK_ECE)
			ca->acked_bytes_ecn += acked_bytes;
	}

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {
		u64 bytes_ecn = ca->acked_bytes_ecn;
		u32 alpha = ca->mdtcp_alpha;
		/* alpha = (1 - g) * alpha + g * F */
		alpha -= min_not_zero(alpha, alpha >> mdtcp_shift_g);
		if (bytes_ecn) {
			/* If mdtcp_shift_g == 1, a 32bit value would overflow
			 * after 8 Mbytes.
			 */
			bytes_ecn <<= (10 - mdtcp_shift_g);
			do_div(bytes_ecn, max(1U, ca->acked_bytes_total));
			alpha = min(alpha + (u32)bytes_ecn, MDTCP_MAX_ALPHA);
		}

		tp->mdtcp_cong_estimate = alpha;
		/* mdtcp_alpha can be read from mdtcp_get_info() without
		 * synchro, so we ask compiler to not use mdtcp_alpha
		 * as a temporary variable in prior operations.
		 */
		WRITE_ONCE(ca->mdtcp_alpha, alpha);
		mdtcp_reset(tp, ca);

		// if (mpcb && mpcb->cnt_established > 1) {
		// 	mdtcp_set_max_dctcp_alfa(mptcp_meta_sk(sk), alpha);
		// }

	}


	if (ntohs(inet->inet_sport) != 5001 && ca->debug) {
		printk("ktime: %lu.%09lu cwnd: %u dctcp-alfa: %u srcip %pI4/%u dstip %pI4/%u rtt: %u cong_est %u\n",
				(unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec, tp->snd_cwnd, ca->mdtcp_alpha, &inet->inet_saddr,
				ntohs(inet->inet_sport), &inet->inet_daddr,
				ntohs(inet->inet_dport), tp->srtt_us >> 3,tp->mdtcp_cong_estimate);
	}

	/*if (flags && CA_ACK_ECE) {
	  unsigned int cwnd=mdtcp_ssthresh(sk);
	  if(cwnd!=tp->snd_cwnd)
	  tp->snd_cwnd=cwnd;
	  }*/

}

static void mdtcp_update_ack_reserved(struct sock *sk, enum tcp_ca_event ev)

{
	struct mdtcp *ca = inet_csk_ca(sk);

	switch (ev) {
		case CA_EVENT_DELAYED_ACK:
			if (!ca->delayed_ack_reserved)
				ca->delayed_ack_reserved = 1;
			break;
		case CA_EVENT_NON_DELAYED_ACK:
			if (ca->delayed_ack_reserved)
				ca->delayed_ack_reserved = 0;
			break;
		default:
			/* Don't care for the rest. */
			break;
	}
}



static u32 mdtcp_cwnd_undo(struct sock *sk)
{
	const struct mdtcp *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static inline void mdtcp_set_forced(const struct sock *meta_sk, bool force)
{
	((struct mdtcp *)inet_csk_ca(meta_sk))->forced_update = force;
}



// static void mdtcp_compute_cwnd_total(const struct sock *sk)
// {
// 	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
// 	const struct sock *sub_sk;
// 	u64 sum = 0;

// 	if (!mpcb)
// 		return;

// 	/* Only one subflow left - fall back to normal reno-behavior
// 	 * (set alpha to 1)
// 	 */
// 	if (mpcb->cnt_established <= 1)
// 		return;

// 	 Do regular alpha-calculation for multiple subflows 
// 	/* Find the max numerator of the alpha-calculation */
// 	mptcp_for_each_sk(mpcb, sub_sk) {
// 		struct tcp_sock *sub_tp = tcp_sk(sub_sk);

// 		if (!mdtcp_sk_can_send(sub_sk))
// 			continue;
// 		sum += (sub_tp->mss_cache * sub_tp->snd_cwnd);
// 	}

// 	sum = (sum >> 3);
// 	sum += (7 * (mdtcp_get_cwnd_total(mptcp_meta_sk(sk)) >> 3));
// 	mdtcp_set_cwnd_total(mptcp_meta_sk(sk), sum);

// }


static void mdtcp_recalc_alpha(const struct sock *sk)
{
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	const struct sock *sub_sk;
	int min_rtt = 1, can_send = 0;
	u64  sum_denominator = 0, alpha = 1;
	// max_numerator = 0,
	// struct tcp_sock *sub_tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct mdtcp *ca = inet_csk_ca(sk);
	struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(), ca->start));

	if (!mpcb)
		return;

	/* Only one subflow left - fall back to normal reno-behavior
	 * (set alpha to 1)
	 */
	if (mpcb->cnt_established <= 1)
		goto exit;

	/* Do regular alpha-calculation for multiple subflows */
	/* Find the max numerator of the alpha-calculation */
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);
		// u64 tmp;
		if (!mdtcp_sk_can_send(sub_sk))
			continue;
		can_send++;

		/* We need to look for the path, that provides the max-value.
		 * Integer-overflow is not possible here, because
		 * tmp will be in u64.
		 */

		if (min_rtt == 1 || sub_tp->srtt_us < min_rtt)
			min_rtt = sub_tp->srtt_us;
	}

	/* No subflow is able to send - we don't care anymore */
	if (unlikely(!can_send))
		goto exit;

	/* Calculate the denominator */
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);
		if (!mdtcp_sk_can_send(sub_sk))
			continue;

		sum_denominator += div_u64(mdtcp_scale(sub_tp->snd_cwnd, alpha_scale_den) * min_rtt, sub_tp->srtt_us);

	}


	if (unlikely(!sum_denominator)) {
		pr_err("%s: sum_denominator == 0, cnt_established:%d\n",
				__func__, mpcb->cnt_established);
		mptcp_for_each_sk(mpcb, sub_sk) {
			struct tcp_sock *sub_tp = tcp_sk(sub_sk);
			pr_err("%s: pi:%d, state:%d\n, rtt:%u, cwnd: %u",
					__func__, sub_tp->mptcp->path_index,
					sub_sk->sk_state, sub_tp->srtt_us,
					sub_tp->snd_cwnd);
		}
	}
	// u64 sum_cwnd = mdtcp_get_cwnd_total(mptcp_meta_sk(sk));
	// alpha = div64_u64(mdtcp_scale(sum_cwnd, alpha_scale_num), sum_denominator);
	alpha = div64_u64(mdtcp_scale(1, alpha_scale_num), sum_denominator);

	// alpha = div64_u64(mdtcp_scale(best_cwnd, alpha_scale_num),sum_denominator);

	if (ntohs(inet->inet_sport) != 5001 && ca->debug) {
		printk("ktime: %lu.%09lu mpalfa: %llu  srcip %pI4/%u dstip %pI4/%u sub %u\n",
				(unsigned long) tv.tv_sec, (unsigned long) tv.tv_nsec, alpha, &inet->inet_saddr,
				ntohs(inet->inet_sport), &inet->inet_daddr,
				ntohs(inet->inet_dport), mpcb->cnt_subflows);
	}

	if (unlikely(!alpha))
		alpha = 1;



exit:
	mdtcp_set_alpha(mptcp_meta_sk(sk), alpha);

}

static void mdtcp_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct mdtcp *ca = inet_csk_ca(sk);
	// struct inet_sock *inet=inet_sk(sk);

	if (mptcp(tcp_sk(sk)) && ((tp->ecn_flags & TCP_ECN_OK) ||
				(sk->sk_state == TCP_LISTEN ||
				 sk->sk_state == TCP_CLOSE))) {

		mdtcp_set_forced(mptcp_meta_sk(sk), 0);
		// mdtcp_set_alfa_flag(mptcp_meta_sk(sk), 0);
		// mdtcp_set_max_dctcp_alfa(mptcp_meta_sk(sk), min(mdtcp_alpha_on_init, MDTCP_MAX_ALPHA));
		mdtcp_set_alpha(mptcp_meta_sk(sk), 1);

		// mdtcp_set_cwnd_total(mptcp_meta_sk(sk), 0);

		ca->start = ktime_get();
		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;
		ca->mdtcp_alpha = min(mdtcp_alpha_on_init, MDTCP_MAX_ALPHA);
		ca->delayed_ack_reserved = 0;
		ca->loss_cwnd = 0;
		ca->ce_state = 0;
		ca->debug=mdtcp_debug;
		
		mdtcp_reset(tp, ca);
		return;
	}


	/* If we do not mdtcp, behave like reno: return */
}


static void mdtcp_state(struct sock *sk, u8 ca_state)
{
	if (!mptcp(tcp_sk(sk)))
		return;
	mdtcp_set_forced(mptcp_meta_sk(sk), 1);

	if (mdtcp_clamp_alpha_on_loss && ca_state == TCP_CA_Loss) {
		struct mdtcp *ca = inet_csk_ca(sk);

		/* If this extension is enabled, we clamp mdtcp_alpha to
		 * max on packet loss; the motivation is that mdtcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 */
		ca->mdtcp_alpha = MDTCP_MAX_ALPHA;
	}
}


static void mdtcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct mptcp_cb *mpcb = tp->mpcb;
	// const struct sock *sub_sk;
	// struct inet_sock *inet=inet_sk(sk);
	// struct mdtcp *ca = inet_csk_ca(sk);
	// struct timespec tv = ktime_to_timespec(ktime_sub(ktime_get(),ca->start));
	int snd_cwnd = 0;
	u32 old_cwnd = 0;

	if (!mptcp(tp)) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		/* In "safe" area, increase. */
		tcp_slow_start(tp, acked);
		// mdtcp_compute_cwnd_total(sk);
		mdtcp_recalc_alpha(sk);

		return;
	}

	if (mdtcp_get_forced(mptcp_meta_sk(sk))) {
		// mdtcp_compute_cwnd_total(sk);
		mdtcp_recalc_alpha(sk);
		mdtcp_set_forced(mptcp_meta_sk(sk), 0);
	}

	if (mpcb->cnt_established > 1) {
		u64 alpha = mdtcp_get_alpha(mptcp_meta_sk(sk));

		// u64 sum;

		// mptcp_for_each_sk(mpcb, sub_sk) {
		// 	struct tcp_sock *sub_tp = tcp_sk(sub_sk);
		// 	if (!mdtcp_sk_can_send(sub_sk))
		// 		continue;
		// 	// sum+=sub_tp->snd_cwnd;

		// 	sum += (sub_tp->mss_cache * sub_tp->snd_cwnd);
		// }

		// sum=mdtcp_get_cwnd_total(mptcp_meta_sk(sk));

		/* This may happen, if at the initialization, the mpcb
		 * was not yet attached to the sock, and thus
		 * initializing alpha failed.
		 */
		if (unlikely(!alpha))
			alpha = 1;
		snd_cwnd = (int) div_u64 ((u64) mdtcp_scale(1, alpha_scale), alpha);


		// snd_cwnd = (int) div_u64 ((u64) mdtcp_scale(sum, alpha_scale), alpha);

		/* snd_cwnd_cnt >= max (scale * tot_cwnd / alpha, cwnd)
		 * Thus, we select here the max value.
		 */
		if (snd_cwnd < tp->snd_cwnd)
			snd_cwnd = tp->snd_cwnd;
	}
	else {
		//tcp_reno_cong_avoid(sk, ack, acked);
		snd_cwnd = tp->snd_cwnd;
	}

	old_cwnd = tp->snd_cwnd;
	tcp_cong_avoid_ai(tp, snd_cwnd, acked);

	if (old_cwnd < tp->snd_cwnd && mpcb->cnt_established > 1)
		mdtcp_recalc_alpha(sk);
	/*
	   if (mpcb->cnt_established > 1) {
	   if (tp->snd_cwnd_cnt >= snd_cwnd) {
	   if (tp->snd_cwnd < tp->snd_cwnd_clamp) {
	   tp->snd_cwnd++;
	   mdtcp_recalc_alpha(sk);
	   }

	   tp->snd_cwnd_cnt = 0;
	   } else {

	   tp->snd_cwnd_cnt++;
	   }
	   }
	 */

}

static void mdtcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	switch (ev) {
		case CA_EVENT_LOSS:
			mdtcp_recalc_alpha(sk);
		case CA_EVENT_ECN_IS_CE:
			mdtcp_ce_state_0_to_1(sk);
			break;
		case CA_EVENT_ECN_NO_CE:
			mdtcp_ce_state_1_to_0(sk);
			break;
		case CA_EVENT_DELAYED_ACK:
		case CA_EVENT_NON_DELAYED_ACK:
			mdtcp_update_ack_reserved(sk, ev);
			break;
		default:
			/* Don't care for the rest. */
			break;
	}
}




static struct tcp_congestion_ops mdtcp __read_mostly  = {
	.init		= mdtcp_init,
	.in_ack_event   = mdtcp_update_alpha,
	.ssthresh	= mdtcp_ssthresh,
	.cong_avoid	= mdtcp_cong_avoid,
	.undo_cwnd	= mdtcp_cwnd_undo,
	.cwnd_event	= mdtcp_cwnd_event,
	.set_state	= mdtcp_state,
	.owner		= THIS_MODULE,
	.flags		= TCP_CONG_NEEDS_ECN,
	.name		= "mdtcp",
};


static int __init mdtcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct mdtcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&mdtcp);
}

static void __exit mdtcp_unregister(void)
{
	tcp_unregister_congestion_control(&mdtcp);
}

module_init(mdtcp_register);
module_exit(mdtcp_unregister);

MODULE_AUTHOR("Christoph Paasch, Sébastien Barré, Daniel Borkmann, Florian Westphal, Glenn Judd, Dejene Boru Oljira");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MDTCP COUPLED CONGESTION CONTROL ALGORITHM");
MODULE_VERSION("0.1");
