# Usage-Dependent Quality of Service

This repository contains the Linux implementation of Usage-Dependent Quality of Service (UD-QoS), which was proposed in the Paper "Usage-Dependent Quality of Service for Free WiFi Networks" at ICCCN 2024.

# Info

The paper introduced UD-QoS as three components. The implementation has only two components because the monitoring functionality is integrated into the other two components. The new qdisc implements the scheduling component and the congestion avoidance is implemented inside a new action for a filter.

There are two implemented versions of UD-QoS. The two versions differ in the way the monitoring is implemented. One version uses a sliding window approach and the other version stores the packet sizes explicitly.

The code was developed using Linux kernel version *6.5.0-14-generic*.

# Requirements

Update the tc commandline program with the new qdisc and action:

```
cd iproute2
sudo make install
```

# Configuration

Change parameters in the kernel modules

### Qdisc (sch_ud_qos.c)

For example to set the threshold for the highest priority class:

```
q->thresholds[0] = 12500; # line 364 in approach_withSlidingWindow 
```

### Filter Action (act_ud_qos.c)

For example to adjust the number of classes, the threshold for the highest priority class and the drop probability:

```
#define NUMBER_CLASSES 3 # line 30 in approach_withSlidingWindow 
ud_qos.thresholds[0] = 250000; # line 403 in approach_withSlidingWindow 
ud_qos.dropProbability[0] = 0; # line 406 in approach_withSlidingWindow 
```

# Build and Start

First define the interface where UD-QoS should be set in the *add.sh*.
To build and add the UD-QoS to the interface run the following command:

```
cd approach_withSlidingWindow
sudo ./add.sh
```
