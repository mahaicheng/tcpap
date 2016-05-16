# Copyright (c) 2000 University of Southern California.
#  All rights reserved.                                            
#                                                                
#  Redistribution and use in source and binary forms are permitted
#  provided that the above copyright notice and this paragraph are
#  duplicated in all such forms and that any documentation, advertising
#  materials, and other materials related to such distribution and use
#  acknowledge that the software was developed by the University of
#  Southern California, Information Sciences Institute.  The name of the
#  University may not be used to endorse or promote products derived from
#  this software without specific prior written permission.
#  
#  THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#
#  Example test program for the visibility-based shadowing propagation model
#  Wei Ye, weiye@isi.edu, 2000


# ======================================================================
# Define options
# ======================================================================

set opt(chan)	Channel/WirelessChannel
#set opt(prop)	Propagation/Shadowing
set opt(netif)	Phy/WirelessPhy
set opt(mac)	Mac/802_11
set opt(ifq)	Queue/DropTail/PriQueue
set opt(ll)		LL
set opt(ant)	Antenna/OmniAntenna
set opt(adhocRouting)   DSDV
set opt(x)		100   ;# X dimension of the topography
set opt(y)		100   ;# Y dimension of the topography
set opt(ifqlen)	50	      ;# max packet in ifq
set opt(seed)	0.0
set opt(tr) 	shadowing-vis.tr    ;# trace file
set opt(nam)	shadowing-vis.nam   ;# nam trace file
set opt(nn) 	2             ;# how many nodes are simulated
set opt(stop)	200.0		;# simulation time

# =====================================================================
# Other default settings

LL set mindelay_		50us
LL set delay_			25us
LL set bandwidth_		0	;# not used

Agent/Null set sport_		0
Agent/Null set dport_		0

Agent/CBR set sport_		0
Agent/CBR set dport_		0


Queue/DropTail/PriQueue set Prefer_Routing_Protocols    1

# unity gain, omni-directional antennas
# set up the antennas to be centered in the node and 1.5 meters above it
Antenna/OmniAntenna set X_ 0
Antenna/OmniAntenna set Y_ 0
Antenna/OmniAntenna set Z_ 0.5
Antenna/OmniAntenna set Gt_ 1.0
Antenna/OmniAntenna set Gr_ 1.0

# Initialize the SharedMedia interface with parameters to make
# it work like the 914MHz Lucent WaveLAN DSSS radio interface
Phy/WirelessPhy set CPThresh_ 10.0
Phy/WirelessPhy set CSThresh_ 1.559e-11
# below is original
#Phy/WirelessPhy set RXThresh_ 3.652e-10
# 95% pkts can be correctly received at 20m for 3/5.
Phy/WirelessPhy set RXThresh_ 3.61705e-09
Phy/WirelessPhy set bandwidth_ 2e6
Phy/WirelessPhy set Pt_ 0.2818
Phy/WirelessPhy set freq_ 914e+6 
Phy/WirelessPhy set L_ 1.0

# Pt_ is transmitted signal power. The propagation model and Pt_ determines
# the received signal power of each packet. The packet can not be correctly
# received if received power is below RXThresh_.

# ======================================================================
# Main Program
# ======================================================================


#
# Initialize Global Variables
#

# create simulator instance

set ns_		[new Simulator]

# set wireless channel
#set wchan	[new $opt(chan)]

#define propagation models
# pathlossExp_ is path-loss exponent, for predicting mean received power
# std_db_ is shadowing deviation (dB), reflecting how large the propagation
# property changes within the environment.
# dist0_ is a close-in reference distance
#
set goodProp	[new Propagation/Shadowing]
$goodProp set pathlossExp_ 2.0
$goodProp set std_db_ 3.0
$goodProp set dist0_ 30.0
$goodProp seed predef 0

set badProp	[new Propagation/Shadowing]
$badProp set pathlossExp_ 3.0
$badProp set std_db_ 5.0
$badProp set dist0_ 1.0
$badProp seed predef 1

#visibility-based shadowing model: line of sight or not using a bitmap
set prop [new Propagation/ShadowingVis]
$prop get-bitmap environment.pnm
# set number of pixels per meter
$prop set-ppm 5
# add previously defined models
$prop add-models $goodProp $badProp

# define topology
set wtopo	[new Topography]
$wtopo load_flatgrid $opt(x) $opt(y)

# create trace object for ns and nam

set tracefd	[open $opt(tr) w]
set namtrace    [open $opt(nam) w]


$ns_ trace-all $tracefd
$ns_ namtrace-all-wireless $namtrace $opt(x) $opt(y)

# use new trace file format
$ns_ use-newtrace 


#
# Create God
#
set god_ [create-god $opt(nn)]

#
# define how node should be created
#

#global node setting

$ns_ node-config  -adhocRouting $opt(adhocRouting) \
		 -llType $opt(ll) \
		 -macType $opt(mac) \
		 -ifqType $opt(ifq) \
		 -ifqLen $opt(ifqlen) \
		 -antType $opt(ant) \
		 -propInstance $prop \
		 -phyType $opt(netif) \
		 -channel [new $opt(chan)] \
		 -topoInstance $wtopo \
		 -agentTrace OFF \
		 -routerTrace OFF \
		 -macTrace ON

#
#  Create the specified number of nodes [$opt(nn)] and "attach" them
#  to the channel. 

for {set i 0} {$i < $opt(nn) } {incr i} {
	set node_($i) [$ns_ node]	
}


# 
# Define node positions
#
# line of sight
$node_(0) set X_ 0.0
$node_(0) set Y_ 50.0
$node_(0) set Z_ 0.0
$node_(1) set X_ 0.0
$node_(1) set Y_ 100.0
$node_(1) set Z_ 0.0

# obstructed
$ns_ at 50.0 "$node_(1) set X_ 70.0"
$ns_ at 50.0 "$node_(1) set Y_ 80.0"

# line of sight
$ns_ at 100.0 "$node_(1) set X_ 20.0"
$ns_ at 100.0 "$node_(1) set Y_ 50.0"

# obstructed
$ns_ at 150.0 "$node_(1) set X_ 60.0"
$ns_ at 150.0 "$node_(1) set Y_ 5.0"

set udp_(0) [new Agent/UDP]
$ns_ attach-agent $node_(0) $udp_(0)
set null_(0) [new Agent/Null]
$ns_ attach-agent $node_(1) $null_(0)
set cbr_(0) [new Application/Traffic/CBR]
$cbr_(0) set packetSize_ 128
$cbr_(0) set interval_ 5.0
$cbr_(0) set random_ 1
$cbr_(0) set maxpkts_ 100
$cbr_(0) attach-agent $udp_(0)
$ns_ connect $udp_(0) $null_(0)
$ns_ at 1.0 "$cbr_(0) start"


# Define node initial position in nam

for {set i 0} {$i < $opt(nn)} {incr i} {

    # 20 defines the node size in nam, must adjust it according to your scenario
    # The function must be called after mobility model is defined
    
    $ns_ initial_node_pos $node_($i) 20
}


#
# Tell nodes when the simulation ends
#
for {set i 0} {$i < $opt(nn) } {incr i} {
    $ns_ at $opt(stop).000000001 "$node_($i) reset";
}
# tell nam the simulation stop time
$ns_ at  $opt(stop)	"$ns_ nam-end-wireless $opt(stop)"

$ns_ at  $opt(stop).000000001 "puts \"NS EXITING...\" ; $ns_ halt"


puts "Starting Simulation..."
$ns_ run




