#!/bin/sh

INTERFACE="enp7s0f3"


make

# add UD-QoS qdisc
sudo insmod sch_ud_qos.ko
sudo tc qdisc replace dev $INTERFACE parent root ud_qos bands 3

# add UD-QoS filter + action
sudo insmod act_ud_qos.ko
sudo tc qdisc add dev $INTERFACE clsact
sudo tc filter add dev $INTERFACE ingress matchall action ud_qos sdata "irrelevant"

echo 'Done'
