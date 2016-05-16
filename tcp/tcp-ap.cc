/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- *
*
 * Copyright (c) 2005 University of Dortmund.
 * All rights reserved.                                            
 *                                                                
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation, advertising
 * materials, and other materials related to such distribution and use
 * acknowledge that the software was developed by the University of
 * Dortmund, Mobile Computing Systems Group.  The name of the
 * University may not be used to endorse or promote products derived from
 * this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * 
 
* Project Reliable Data Transport over Multihop Wireless Networks
 * Principal Investigator: Christoph Lindemann
 * Ph.D. Student: Sherif M. ElRakabawy
 *
 * The development of TCP with Adaptive Pacing, TCP-AP, and its ns-2 
 * simulation software has been funded in part by the German Research 
 * Council (DFG). A detailed description of TCP-AP and a comparative 
 * performance study is given in: 
 * S. ElRakabawy, A. Klemm, and C. Lindemann, TCP with Adaptive
 * Pacing for Multihop Wireless Networks, Proc. ACM
 * International Symposium on Mobile Ad Hoc Networking and
 * Computing (MobiHoc 2005), Urbana-Champaign, IL, USA, May 2005.
 *
 * This implementation of TCP-AP is based on TCP NewReno.
 *
 * Author: Sherif M. ElRakabawy
 * <sme@mobicom.cs.uni-dortmund.de>
 * September 2005	
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "tcp.h"
#include "flags.h"
#include "math.h"
#include "random.h"

#define max(a,b)        a > b ? a : b
#define min(a,b)        a < b ? a : b

/* Set maximum n_hop_delay_ samples history size 
 * NOTE: this value should always be larger than history_.
 */
#define MAXHISTORY	200

/* Set maximum number of packets waiting to be transmitted
 *  NOTE: this value should always be larger than window_ (wnd_ in tcp.cc).
 */ 
#define MAXPKTS2SEND	200

class NewRenoAPTcpAgent;

/* Pacing timer for rate-based transmission */
class PaceTimer : public TimerHandler {
public: 
	PaceTimer(NewRenoAPTcpAgent *a) : TimerHandler() { a_ = a; }
protected:
	virtual void expire(Event *e);
	NewRenoAPTcpAgent *a_;
};

class NewRenoAPTcpAgent : public virtual NewRenoTcpAgent {
friend class PaceTimer;
public:
	NewRenoAPTcpAgent();
	virtual void recv(Packet *pkt, Handler *);
	virtual void timeout(int tno);
	virtual void output(int seqno, int reason = 0);

protected:
	virtual void pace_timeout();		/* Called after the pace timer expires */
	virtual void set_pace_timer();		/* Reschedule the pace timer */
	virtual void calc_variation();		/* Calculate variation of the n_hop_delay_ samples 
						   (equivalent to the variation of the RTT samples 
						   since n_hop_delay_ is simply a fraction of RTT) */
	
	PaceTimer pace_timer_;			/* Pacing timer for rate-based transmission */
	
	int n_factor_;				/* Spatial reuse constraint factor which mainly
						   depends on ratio between transmission range 
						   and interference range (default is 4 for 250m 
						   transmission range and 550m interference/cs ranges) */
	int ispaced_;
	int initial_pace_;
	int samplecount_;
	int history_;				/* n_hop_delay_ samples history size */
	int pkts_to_send_;			/* Number of packets waiting to be transmitted */
	int seqno_[MAXPKTS2SEND];		/* Sequence numbers of packets waiting to be transmitted */
	double delaybound_;			/* An upper bound for the n_hop_delay_ samples */
	double rate_interval_;			/* time between successive packet transmissions */
	double n_hop_delay_;			/* How much to delay the transmission to avoid hidden 
						   terminal induced collisions */
	double avg_n_hop_delay_;
	double avg_queuing_delay_;
	double alpha_;				/* smoothing factor for avg_n_hop_delay_ */
	double gamma_;				/* smoothing factor for avg_queuing_delay_ */
	double samples[MAXHISTORY];		/* n_hop_delay_ samples */	
	double coeff_var_;			/* coefficient of variation of n_hop_delay_ samples */
	double adev_;				/* mean absolute deviation n_hop_delay_ samples */
	double ll_bandwidth_;			/* link layer bandwidth (in bits/s) */
};

static class NewRenoAPTcpClass : public TclClass {
public:
	NewRenoAPTcpClass() : TclClass("Agent/TCP/Newreno/AP") {}
	TclObject* create(int, const char*const*) {
		return (new NewRenoAPTcpAgent());
	}
} class_newreno_ap;


void PaceTimer::expire(Event*) {
	a_->pace_timeout();
}

NewRenoAPTcpAgent::NewRenoAPTcpAgent() : NewRenoTcpAgent(),
	n_factor_(4), ispaced_(1), initial_pace_(0), pkts_to_send_(0),
	samplecount_(0), rate_interval_(0.05), alpha_(0.7), 
	gamma_(0.5), history_(50), delaybound_(0.5), ll_bandwidth_(2e6),
	n_hop_delay_(0), avg_n_hop_delay_(0), avg_queuing_delay_(0), 
	pace_timer_(this) {
	
	bind("n_factor_", &n_factor_);
	bind("rate_interval_", &rate_interval_);
	bind("n_hop_delay_", &n_hop_delay_);
	bind("avg_n_hop_delay_", &avg_n_hop_delay_);
	bind("coeff_var_", &coeff_var_);
	bind("adev_", &adev_);
	bind("history_", &history_);
	bind("delaybound_", &delaybound_);
	bind("alpha_", &alpha_);
	bind("ll_bandwidth_", &ll_bandwidth_);

	if (history_ > MAXHISTORY) {
		fprintf(stderr, "TCP-AP: history_ > MAXHISTORY, adjust MAXHISTORY in tcp-ap.cc\n");
		exit(-1);
	}
	if (wnd_ > MAXPKTS2SEND) {
                //fprintf(stderr, "TCP-AP: window_ > MAXPKTS2SEND, adjust MAXPKTS2SEND in tcp-ap.cc\n");
                fprintf(stderr, "TCP-AP: window_ > MAXPKTS2SEND, adjust MAXPKTS2SEND in tcp-ap.cc wnd:%.9f\n", wnd_);
		printf("-------%f--------\n", wnd_);
		assert(0);///SEMIDEBUG
                exit(-1);
        }
}

void NewRenoAPTcpAgent::recv(Packet *pkt, Handler *hand) {
	
	hdr_tcp *tcph = hdr_tcp::access(pkt);
	hdr_cmn *ch = hdr_cmn::access(pkt);
	if (ispaced_ == 0) {
		ispaced_ = 1;
		initial_pace_ = 0;
	}

	int numhops = int(ch->num_forwards());
	double rtt = Scheduler::instance().clock() - tcph->ts_echo();
	
	/* describes packet overhead (headers of TCP, IP, MAC ..) */
	double overhead = 112.0;
	double datasize = size_ + overhead;
	/* TCP ACKs only consist of headers */
	double acksize = overhead;
	/* bandwidth in bytes/s */
	double bandwidth = ll_bandwidth_ / 8;
	double queuing_delay = (1.0/2.0) * (rtt/numhops - (datasize+acksize)/bandwidth);
	if (queuing_delay > delaybound_) {
		queuing_delay = avg_queuing_delay_;
	}
	double calc_data_delay = (double)numhops * (queuing_delay + (datasize/bandwidth));
	double calc_ack_delay = (double)numhops * (queuing_delay + (acksize/bandwidth));

	avg_queuing_delay_ = gamma_ * avg_queuing_delay_ + (1.0-gamma_) * queuing_delay;
	double one_hop = calc_data_delay / (double)numhops;
	
	if (tcph->ts() > 0.0) {
		if (numhops >= n_factor_) {
			n_hop_delay_ = one_hop * (double)n_factor_;
		}
		else {
			n_hop_delay_ = one_hop; 
		}
	}
	else {
		n_hop_delay_ = 0;
	}

	if (n_hop_delay_ > 0.0 && n_hop_delay_ < delaybound_) {
		if (avg_n_hop_delay_ == 0.0) {
			avg_n_hop_delay_ = n_hop_delay_;
		} else {
			avg_n_hop_delay_ = alpha_ * avg_n_hop_delay_ + (1.0 - alpha_) * n_hop_delay_;
		}
	}	
	calc_variation();
	NewRenoTcpAgent::recv(pkt, hand);
}

void NewRenoAPTcpAgent::calc_variation() {
	
	double sumsamples = 0;
	double mean = 0;
	double dev_1 = 0;
	double dev_1_2 = 0;
	double std_dev = 0;
	double std_dev2 = 0;

	if (n_hop_delay_ > 0.0 && n_hop_delay_ < delaybound_) {
		if (samplecount_ < history_) {
			samples[samplecount_] = n_hop_delay_;
			samplecount_++;	
		} 
		else {
			for (int i = 0; i < samplecount_ - 1; i++) {
				samples[i] = samples[i+1];
			}
			samples[samplecount_ - 1] = n_hop_delay_;
		}
	} else {
		return;
	}
	for (int i = 0; i < samplecount_; i++) {
		sumsamples+= samples[i];
	}
	mean = sumsamples / samplecount_;
	
	for (int i = 0; i < samplecount_; i++) {
		double diff_2 = samples[i] - mean;
		dev_1_2 += pow(diff_2, 2);
		double diff = fabs(samples[i] - mean);
		dev_1 += diff;
	}
	if (dev_1 > 0.0) {
		std_dev = dev_1/samplecount_;	
		std_dev2 = sqrt(dev_1_2/samplecount_);
	}
	else {
		return;
	}
	
	adev_ = std_dev / mean;
	coeff_var_ = std_dev2 / mean;
}

void NewRenoAPTcpAgent::output(int seqno, int reason) {

	if (ispaced_ != 1) {
                NewRenoTcpAgent::output(seqno, reason);
                return;
        }
        if (reason == TCP_REASON_DUPACK) {
                pace_timer_.force_cancel();
                if (pkts_to_send_ > 0) {
                        pkts_to_send_ = 0;
                        ispaced_ = 0;
                }
                NewRenoTcpAgent::output(seqno, reason);
                return;
        }
        seqno_[pkts_to_send_] = seqno;
        pkts_to_send_++;
        if (initial_pace_ != 1) {
                pace_timeout();
                initial_pace_ = 1;
        }
}
	
void NewRenoAPTcpAgent::pace_timeout() 
{
	if (ispaced_ != 1) {
		fprintf(stderr, "Error, shouldn't be in pacing mode.\n");
		exit(-1);
	}
	if (pkts_to_send_ > 0) {
		NewRenoTcpAgent::output(seqno_[0], 0);
		for (int i = 0; i < pkts_to_send_; i++) {
			seqno_[i] = seqno_[i+1];
		}	
		pkts_to_send_--;
	}	
	set_pace_timer();
}

void NewRenoAPTcpAgent::set_pace_timer() {
	
		if (avg_n_hop_delay_ > 0.0) {
				/* Instead of the coefficient of variation we can alternatively 
				   use the mean absolute deviation to avoid computing the sqrt 
				   which saves us processor time and energy. 
				 */
				   
				rate_interval_ = (1 + 2 * adev_) * avg_n_hop_delay_;
		}
			
	pace_timer_.resched(rate_interval_);
}

void NewRenoAPTcpAgent::timeout(int tno) {
	
	/* retransmit timer */
	if (tno == TCP_TIMER_RTX) {
		pace_timer_.force_cancel();
		ispaced_ = 0;
		pkts_to_send_ = 0;

		// There has been a timeout - will trace this event
		trace_event("TIMEOUT");

	        if (cwnd_ < 1) cwnd_ = 1;
		if (highest_ack_ == maxseq_ && !slow_start_restart_) {
			/*
			 * TCP option:
			 * If no outstanding data, then don't do anything.  
			 */
			 // Should this return be here?
			 // What if CWND_ACTION_ECN and cwnd < 1?
			 // return;
		} else {
			recover_ = maxseq_;
			if (highest_ack_ == -1 && wnd_init_option_ == 2)
				/* 
				 * First packet dropped, so don't use larger
				 * initial windows. 
				 */
				wnd_init_option_ = 1;
			if (highest_ack_ == maxseq_ && restart_bugfix_)
			       /* 
				* if there is no outstanding data, don't cut 
				* down ssthresh_.
				*/
				slowdown(CLOSE_CWND_ONE);
			else if (highest_ack_ < recover_ &&
			  last_cwnd_action_ == CWND_ACTION_ECN) {
			       /*
				* if we are in recovery from a recent ECN,
				* don't cut down ssthresh_.
				*/
				slowdown(CLOSE_CWND_ONE);
			}
			else {
				++nrexmit_;
				last_cwnd_action_ = CWND_ACTION_TIMEOUT;
				slowdown(CLOSE_SSTHRESH_HALF|CLOSE_CWND_RESTART);
			}
		}
		/* Since:
		   (1) we react upon incipient congestion by throttling the transmission 
		       rate of TCP-AP
		   (2) we rarely get any buffer overflow in multihop networks with consistent
		       link layer bandwidth
		   then we don't need to back off (verified by simulations). 
		 */
		reset_rtx_timer(0,0);
		
		last_cwnd_action_ = CWND_ACTION_TIMEOUT;
		send_much(0, TCP_REASON_TIMEOUT, maxburst_);
	} 
	else {
		timeout_nonrtx(tno);
	}
}

