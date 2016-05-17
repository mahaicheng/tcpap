/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) 1991-1997 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include "ip.h"
#include "tcp.h"
#include "semitcp.h"
#include <algorithm>
#include <unistd.h>

using namespace std;

void TcpBackoffTimer::expire(Event *)
{
	a_->backoff_timeout();
}

static class SemiTcpClass : public TclClass
{
public:
        SemiTcpClass() : TclClass ( "Agent/TCP/Newreno/Semitcp" ) {}
        TclObject* create ( int, const char*const* ) {
                return ( new SemiTcpAgent() );
        }
} class_semi;

SemiTcpAgent::SemiTcpAgent() : 
			backoffTimer_(this),	
			p_to_mac(nullptr),
			isBackoff_(true),
			initial_backoff_(false),
			cw_(1),
			timeslot_(0.02)
{ 
	
}

void SemiTcpAgent::backoff_timeout()
{
	assert(isBackoff_ == true);
	if (!outgoingPkts.empty())
	{
		int tmpseqno = outgoingPkts.front();
		NewRenoTcpAgent::output(tmpseqno, 0);
		outgoingPkts.pop_front();
	}
	
	setBackoffTimer();
}

int SemiTcpAgent::command ( int argc, const char*const* argv )
{
        if ( argc == 3 && strcmp ( argv[1], "semitcp-get-mac" ) == 0 ) 
		{
                p_to_mac = ( Mac802_11* ) TclObject::lookup ( argv[2] );		
				return p_to_mac == NULL ? TCL_ERROR : TCL_OK;

        } else if ( argc == 2 && strcmp ( argv[1], "get-highest-acked" ) == 0 ) 
		{
                printf ( "highest acked seqno: %d \n", ( int ) highest_ack_ );
                return TCL_OK;
        }
        return TcpAgent::command ( argc, argv );
}

void SemiTcpAgent::output ( int seqno, int reason )
{
	if (!isBackoff_)
	{
		NewRenoTcpAgent::output(seqno, reason);
		return;
	}
	if (reason == TCP_REASON_DUPACK)
	{
		backoffTimer_.force_cancel();
		if (!outgoingPkts.empty())
		{
			outgoingPkts.clear();
			isBackoff_ = false;
		}
		NewRenoTcpAgent::output(seqno, reason);
		return;
	}
	else
	{
		outgoingPkts.push_back(seqno);
	}
	if (!initial_backoff_)
	{
		backoff_timeout();
		initial_backoff_ = true;
	}
	
}

void SemiTcpAgent::recv ( Packet *pkt, Handler* hand)
{
	if (!isBackoff_)
	{
		isBackoff_ = true;
		initial_backoff_ = false;
	}
	NewRenoTcpAgent::recv(pkt, hand);
}

///Called when the retransimition timer times out
void SemiTcpAgent::timeout ( int tno )
{
	/* retransmit timer */
	if (tno == TCP_TIMER_RTX) {
		backoffTimer_.force_cancel();
		isBackoff_ = false;
		outgoingPkts.clear();

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