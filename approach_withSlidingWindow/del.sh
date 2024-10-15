#!/bin/sh

INTERFACE="enp7s0f3"

# del ud-qos
sudo tc qdisc del dev $INTERFACE clsact
sudo tc qdisc del dev $INTERFACE parent root

sudo rmmod act_ud_qos
sudo rmmod sch_ud_qos

echo 'Done'