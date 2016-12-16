#!/bin/bash
echo "add Net1-snort ofport into OVS"
#ovs-vsctl del-port Net1 Net1-snort
ip link add name Net1-snort type veth peer name snort
ovs-vsctl add-port Net1 Net1-snort
echo "get Net-snort ofport number:"
ovs-vsctl get Interface Net1-snort ofport


#echo "add Net1-honeyd ofport into OVS"
#ovs-vsctl del-port Net1 Net1-honeyd
#ip link add name Net1-honeyd type veth peer name honeyd
#ovs-vsctl add-port Net1 Net1-honeyd
#echo "get Net1-honeyd ofport number"
#ovs-vsctl get Interface Net1-honeyd ofport

#ovs-vsctl  add-port  Net1  Net1-honeyd  tag=10 -- set Interface Net1-honeyd type=internal
#ifconfig Net1-honeyd 10.1.0.1


echo "MIH ofport"
ovs-vsctl get Interface Net1-MIH ofport
ovs-vsctl get Interface MIH-e1 ofport
echo "HIH ofport"
ovs-vsctl get Interface Net1-HIH ofport

#ovs-vsctl show
