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
#include <linux/inet_diag.h>

#define DCTCP_MAX_ALPHA	1024U

/* Scaling is done in the numerator with alpha_scale_num and in the denominator
 * with alpha_scale_den.
 *
 * To downscale, we just need to use alpha_scale.
 *
 * We have: alpha_scale = alpha_scale_num / (alpha_scale_den ^ 2)
 */
static int alpha_scale_den = 10;
static int alpha_scale_num = 32;
static int alpha_scale = 22;

struct mdtcp_ccc {
	/*mptcp parameters*/
	u64	alpha;
	bool	forced_update;
	/*dctcp parameters*/
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 dctcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 delayed_ack_reserved;
	u32 loss_cwnd;
	/* end dctcp*/
};

/*DCTCP specifics*/
static unsigned int dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(dctcp_shift_g, uint, 0644);
MODULE_PARM_DESC(dctcp_shift_g, "parameter g for updating dctcp_alpha");

static unsigned int dctcp_alpha_on_init __read_mostly = DCTCP_MAX_ALPHA;
module_param(dctcp_alpha_on_init, uint, 0644);
MODULE_PARM_DESC(dctcp_alpha_on_init, "parameter for initial alpha value");

static unsigned int dctcp_clamp_alpha_on_loss __read_mostly;
module_param(dctcp_clamp_alpha_on_loss, uint, 0644);
MODULE_PARM_DESC(dctcp_clamp_alpha_on_loss,
                 "parameter for clamping alpha on loss");

static struct tcp_congestion_ops mdtcp_reno;

static void mdtcp_reset(const struct tcp_sock *tp, struct mdtcp_ccc *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
}

/*end DCTCP*/


static inline int mdtcp_ccc_sk_can_send(const struct sock *sk)
{
	return mptcp_sk_can_send(sk) && tcp_sk(sk)->srtt_us;
}

static inline u64 mdtcp_get_alpha(const struct sock *meta_sk)
{
	return ((struct mdtcp_ccc *)inet_csk_ca(meta_sk))->alpha;
}

static inline void mdtcp_set_alpha(const struct sock *meta_sk, u64 alpha)
{
	((struct mdtcp_ccc *)inet_csk_ca(meta_sk))->alpha = alpha;
}

static inline u64 mdtcp_ccc_scale(u32 val, int scale)
{
	return (u64) val << scale;
}

static inline bool mdtcp_get_forced(const struct sock *meta_sk)
{
	return ((struct mdtcp_ccc *)inet_csk_ca(meta_sk))->forced_update;
}

static inline void mdtcp_set_forced(const struct sock *meta_sk, bool force)
{
	((struct mdtcp_ccc *)inet_csk_ca(meta_sk))->forced_update = force;
}

static void mdtcp_ccc_recalc_alpha(const struct sock *sk)
{
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	const struct sock *sub_sk;
	int best_cwnd = 0, best_rtt = 0, can_send = 0;
	u64 max_numerator = 0, sum_denominator = 0, alpha = 1;

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
		u64 tmp;

		if (!mdtcp_ccc_sk_can_send(sub_sk))
			continue;

		can_send++;

		/* We need to look for the path, that provides the max-value.
		 * Integer-overflow is not possible here, because
		 * tmp will be in u64.
		 */
		tmp = div64_u64(mdtcp_ccc_scale(1,
		                                alpha_scale_num), (u64)sub_tp->srtt_us);

		// tmp = div64_u64(mdtcp_ccc_scale(sub_tp->snd_cwnd,
		//                                 alpha_scale_num), (u64)sub_tp->srtt_us * sub_tp->srtt_us)

		if (tmp >= max_numerator) {
			max_numerator = tmp;
			best_cwnd = sub_tp->snd_cwnd;
			best_rtt = sub_tp->srtt_us;
		}
	}

	/* No subflow is able to send - we don't care anymore */
	if (unlikely(!can_send))
		goto exit;

	/* Calculate the denominator */
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);

		if (!mdtcp_ccc_sk_can_send(sub_sk))
			continue;

		// sum_denominator += div_u64(
		//                        mdtcp_ccc_scale(sub_tp->snd_cwnd,
		//                                        alpha_scale_den) * best_rtt,
		//                        sub_tp->srtt_us);

		sum_denominator += div_u64(
		                       mdtcp_ccc_scale(sub_tp->snd_cwnd,
		                                       alpha_scale_den) * best_rtt,
		                       sub_tp->srtt_us);

	}
    
    /*mptcp (not squared in mdtcp*/
	// sum_denominator *= sum_denominator;

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

	// alpha = div64_u64(mdtcp_ccc_scale(best_cwnd, alpha_scale_num), sum_denominator);
	alpha = div64_u64(mdtcp_ccc_scale(1, alpha_scale_num), sum_denominator);

	if (unlikely(!alpha))
		alpha = 1;

exit:
	mdtcp_set_alpha(mptcp_meta_sk(sk), alpha);
}

static void mdtcp_ccc_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	if (mptcp(tcp_sk(sk))) {
		mdtcp_set_forced(mptcp_meta_sk(sk), 0);
		mdtcp_set_alpha(mptcp_meta_sk(sk), 1);
		/*dctcp*/

		if ((tp->ecn_flags & TCP_ECN_OK) ||
		        (sk->sk_state == TCP_LISTEN ||
		         sk->sk_state == TCP_CLOSE)) {
			struct mdtcp_ccc *ca = inet_csk_ca(sk);

			ca->prior_snd_una = tp->snd_una;
			ca->prior_rcv_nxt = tp->rcv_nxt;

			ca->dctcp_alpha = min(dctcp_alpha_on_init, DCTCP_MAX_ALPHA);

			ca->delayed_ack_reserved = 0;
			ca->loss_cwnd = 0;
			ca->ce_state = 0;

			mdtcp_reset(tp, ca);
			return;
		}
		/* No ECN support? Fall back to Reno. Also need to clear
		* ECT from sk since it is set during 3WHS for DCTCP.
		*/
		inet_csk(sk)->icsk_ca_ops = &mdtcp_reno;
		INET_ECN_dontxmit(sk);
		/*dctcp*/

	}
	/* If we do not mptcp, behave like reno: return */
}

static u32 mdtcp_ccc_ssthresh(struct sock *sk)
{
	struct mdtcp_ccc *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->loss_cwnd = tp->snd_cwnd;
	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->dctcp_alpha) >> 11U), 2U);
}

static void mdtcp_ccc_update_dctcp_alpha(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct mdtcp_ccc *ca = inet_csk_ca(sk);
	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;

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
		u32 alpha = ca->dctcp_alpha;

		/* alpha = (1 - g) * alpha + g * F */

		alpha -= min_not_zero(alpha, alpha >> dctcp_shift_g);
		if (bytes_ecn) {
			/* If dctcp_shift_g == 1, a 32bit value would overflow
			 * after 8 Mbytes.
			 */
			bytes_ecn <<= (10 - dctcp_shift_g);
			do_div(bytes_ecn, max(1U, ca->acked_bytes_total));

			alpha = min(alpha + (u32)bytes_ecn, DCTCP_MAX_ALPHA);
		}
		/* dctcp_alpha can be read from dctcp_get_info() without
		 * synchro, so we ask compiler to not use dctcp_alpha
		 * as a temporary variable in prior operations.
		 */
		WRITE_ONCE(ca->dctcp_alpha, alpha);
		mdtcp_reset(tp, ca);
	}
}

/* Minimal DCTP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */

static void mdtcp_ccc_ce_state_0_to_1(struct sock *sk)
{
	struct mdtcp_ccc *ca = inet_csk_ca(sk);
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

static void mdtcp_ccc_ce_state_1_to_0(struct sock *sk)
{
	struct mdtcp_ccc *ca = inet_csk_ca(sk);
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

static void mdtcp_ccc_update_ack_reserved(struct sock *sk, enum tcp_ca_event ev)
{
	struct mdtcp_ccc *ca = inet_csk_ca(sk);

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


static void mdtcp_ccc_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_LOSS)
		mdtcp_ccc_recalc_alpha(sk);
	/*dctcp cwnd_event*/
	else if (event == CA_EVENT_ECN_IS_CE)
		mdtcp_ccc_ce_state_0_to_1(sk);
	else if (event == CA_EVENT_ECN_NO_CE)
		mdtcp_ccc_ce_state_1_to_0(sk);
	else if (event == CA_EVENT_DELAYED_ACK || event == CA_EVENT_NON_DELAYED_ACK)
		mdtcp_ccc_update_ack_reserved(sk, event);
	/*end dctcp*/

}



static void mdtcp_ccc_set_state(struct sock *sk, u8 ca_state)
{
	if (!mptcp(tcp_sk(sk)))
		return;
	/*dctcp max alpha*/
	if(dctcp_clamp_alpha_on_loss && ca_state == TCP_CA_Loss)
	{
		struct mdtcp_ccc *ca = inet_csk_ca(sk);
		/* If this extension is enabled, we clamp dctcp_alpha to
		 * max on packet loss; the motivation is that dctcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 */
		ca->dctcp_alpha = DCTCP_MAX_ALPHA;
	}
	/*end dctcp*/

	mdtcp_set_forced(mptcp_meta_sk(sk), 1);
}


static u32 mdtcp_ccc_cwnd_undo(struct sock *sk)
{
	const struct mdtcp_ccc *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static void mdtcp_ccc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct mptcp_cb *mpcb = tp->mpcb;
	int snd_cwnd;

	if (!mptcp(tp)) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		/* In "safe" area, increase. */
		tcp_slow_start(tp, acked);
		mdtcp_ccc_recalc_alpha(sk);
		return;
	}

	if (mdtcp_get_forced(mptcp_meta_sk(sk))) {
		mdtcp_ccc_recalc_alpha(sk);
		mdtcp_set_forced(mptcp_meta_sk(sk), 0);
	}

	if (mpcb->cnt_established > 1) {
		u64 alpha = mdtcp_get_alpha(mptcp_meta_sk(sk));

		/* This may happen, if at the initialization, the mpcb
		 * was not yet attached to the sock, and thus
		 * initializing alpha failed.
		 */
		if (unlikely(!alpha))
			alpha = 1;

		snd_cwnd = (int) div_u64 ((u64) mdtcp_ccc_scale(1, alpha_scale),
		                          alpha);

		/* snd_cwnd_cnt >= max (scale * tot_cwnd / alpha, cwnd)
		 * Thus, we select here the max value.
		 */
		if (snd_cwnd < tp->snd_cwnd)
			snd_cwnd = tp->snd_cwnd;
	} else {
		snd_cwnd = tp->snd_cwnd;
	}

	if (tp->snd_cwnd_cnt >= snd_cwnd) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp) {
			tp->snd_cwnd++;
			mdtcp_ccc_recalc_alpha(sk);
		}

		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt++;
	}
}

static size_t mdtcp_dctcp_get_info(struct sock *sk, u32 ext, int *attr,
			     union tcp_cc_info *info)
{
	const struct mdtcp_ccc *ca = inet_csk_ca(sk);

	/* Fill it also in case of VEGASINFO due to req struct limits.
	 * We can still correctly retrieve it later.
	 */
	if (ext & (1 << (INET_DIAG_MDTCPINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		memset(&info->mdtcp, 0, sizeof(info->mdtcp));
		if (inet_csk(sk)->icsk_ca_ops != &mdtcp_reno) {
			info->mdtcp.dctcp_enabled = 1;
			info->mdtcp.dctcp_ce_state = (u16) ca->ce_state;
			info->mdtcp.dctcp_alpha = ca->dctcp_alpha;
			info->mdtcp.dctcp_ab_ecn = ca->acked_bytes_ecn;
			info->mdtcp.dctcp_ab_tot = ca->acked_bytes_total;
		}

		*attr = INET_DIAG_MDTCPINFO;
		return sizeof(info->mdtcp);
	}
	return 0;
}

static struct tcp_congestion_ops mdtcp_ccc = {
	.init		= mdtcp_ccc_init,
	.in_ack_event   = mdtcp_ccc_update_dctcp_alpha,
	.ssthresh	= mdtcp_ccc_ssthresh,
	.cong_avoid	= mdtcp_ccc_cong_avoid,
	.undo_cwnd	= mdtcp_ccc_cwnd_undo,
	.cwnd_event	= mdtcp_ccc_cwnd_event,
	.set_state	= mdtcp_ccc_set_state,
	.get_info	= mdtcp_dctcp_get_info,
	.owner		= THIS_MODULE,
	.flags		= TCP_CONG_NEEDS_ECN,
	.name		= "mdtcp",
};

static struct tcp_congestion_ops mdtcp_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= mdtcp_ccc_cong_avoid,
	.cwnd_event	= mdtcp_ccc_cwnd_event,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.owner		= THIS_MODULE,
	.name		= "mdtcp-reno",
};


static int __init mdtcp_ccc_register(void)
{
	BUILD_BUG_ON(sizeof(struct mdtcp_ccc) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&mdtcp_ccc);
}

static void __exit mdtcp_ccc_unregister(void)
{
	tcp_unregister_congestion_control(&mdtcp_ccc);
}

module_init(mdtcp_ccc_register);
module_exit(mdtcp_ccc_unregister);

MODULE_AUTHOR("Christoph Paasch, Sébastien Barré, Daniel Borkmann, Florian Westphal, Glenn Judd, Dejene Boru Oljira");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MDTCP COUPLED CONGESTION CONTROL ALGORITHM");
MODULE_VERSION("0.1");
