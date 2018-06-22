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
 * We have: alpha_scale = alpha_scale_num / (alpha_scale_den)
 */
static int alpha_scale_den = 10;
static int alpha_scale_num = 20;
static int alpha_scale = 10;

struct mdtcp_ccc {
	/*mptcp parameters*/
	u64	alpha;
	bool	forced_update;
	
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
	int  best_rtt = 0, can_send = 0;
	u64  sum_denominator = 0, alpha = 1;
    // max_numerator = 0,
    struct tcp_sock *sub_tp = tcp_sk(sk);
	//struct inet_sock *inet = inet_sk(sk);
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
		if (!mdtcp_ccc_sk_can_send(sub_sk))
			continue;
		can_send++;

		/* We need to look for the path, that provides the max-value.
		 * Integer-overflow is not possible here, because
		 * tmp will be in u64.
		 */

	       if (best_rtt == 0 || sub_tp->srtt_us <= bes_rtt) 
                    {
			best_rtt = sub_tp->srtt_us;
		    }

            // printk("mprtt2:best_rtt %u rtt %u cwnd %u path id %d no subflows %d\n",
              //         best_rtt,sub_tp->srtt_us, sub_tp->snd_cwnd,sub_tp->mptcp->path_index,mpcb->cnt_established);
	}

	/* No subflow is able to send - we don't care anymore */
	if (unlikely(!can_send))
		goto exit;

	/* Calculate the denominator */
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);
		if (!mdtcp_ccc_sk_can_send(sub_sk))
			continue;
		sum_denominator += div_u64(mdtcp_ccc_scale(sub_tp->snd_cwnd, 
                                   alpha_scale_den) * best_rtt, sub_tp->srtt_us);
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
    	
    alpha = div64_u64(mdtcp_ccc_scale(1, alpha_scale_num), sum_denominator);

    if (unlikely(!alpha))
	 alpha = 1;

exit:
	mdtcp_set_alpha(mptcp_meta_sk(sk), alpha);
        
}

static void mdtcp_ccc_init(struct sock *sk)
{
	// const struct tcp_sock *tp = tcp_sk(sk);
	if (mptcp(tcp_sk(sk))) {
		mdtcp_set_forced(mptcp_meta_sk(sk), 0);
		mdtcp_set_alpha(mptcp_meta_sk(sk), 1);
		/*dctcp*/
        mdtcp_dctcp_init(sk);
		/*dctcp*/
	}
	/* If we do not mptcp, behave like reno: return */
}


static void mdtcp_ccc_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_LOSS)
		mdtcp_ccc_recalc_alpha(sk);
	/*dctcp cwnd_event*/
	mdtcp_dctcp_cwnd_event(sk, event);
	/*end dctcp*/
}


static void mdtcp_ccc_set_state(struct sock *sk, u8 ca_state)
{
	if (!mptcp(tcp_sk(sk)))
		return;
	mdtcp_set_forced(mptcp_meta_sk(sk), 1);
	/*dctcp max alpha*/
	mdtcp_dctcp_state(sk, ca_state);
	/*end dctcp*/	
}


static void mdtcp_ccc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct mptcp_cb *mpcb = tp->mpcb;
	int snd_cwnd;
        //struct inet_sock *inet = inet_sk(sk);
	if (!mptcp(tp)) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
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

static size_t mdtcp_ccc_get_info(struct sock *sk, u32 ext, int *attr,
			     union tcp_cc_info *info)
{
	// const struct mdtcp_ccc *ca = inet_csk_ca(sk);

	// /* Fill it also in case of VEGASINFO due to req struct limits.
	//  * We can still correctly retrieve it later.
	//  */
	// if (ext & (1 << (INET_DIAG_MDTCPINFO - 1)) ||
	//     ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
	// 	memset(&info->mdtcp, 0, sizeof(info->mdtcp));
	// 	if (inet_csk(sk)->icsk_ca_ops != &mdtcp_reno) {
	// 		info->mdtcp.dctcp_enabled = 1;
	// 		info->mdtcp.dctcp_ce_state = (u16) ca->ce_state;
	// 		info->mdtcp.dctcp_alpha = ca->dctcp_alpha;
	// 		info->mdtcp.dctcp_ab_ecn = ca->acked_bytes_ecn;
	// 		info->mdtcp.dctcp_ab_tot = ca->acked_bytes_total;
	// 	}

	// 	*attr = INET_DIAG_MDTCPINFO;
	// 	return sizeof(info->mdtcp);
	// }
	return 0;
}

static struct tcp_congestion_ops mdtcp_ccc = {
	.init		= mdtcp_ccc_init,
	.in_ack_event   = mdtcp_dctcp_update_alpha,
	.ssthresh	= mdtcp_dctcp_ssthresh,
	.cong_avoid	= mdtcp_ccc_cong_avoid,
	.undo_cwnd	= mdtcp_dctcp_cwnd_undo,
	.cwnd_event	= mdtcp_ccc_cwnd_event,
	.set_state	= mdtcp_ccc_set_state,
	.get_info	= mdtcp_ccc_get_info,
	.owner		= THIS_MODULE,
	.flags		= TCP_CONG_NEEDS_ECN,
	.name		= "mdtcp",
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
