# Usage-Dependent Quality of Service

This repository contains the Linux implementation of Usage-Dependent Quality of Service (UD-QoS), which was proposed in the Paper "Usage-Dependent Quality of Service for Free WiFi Networks".

# Info

The paper introduced UD-QoS as three components. The implementation has only two components because the monitoring functionality is integrated into the other two components. The new qdisc implements the scheduling component and the congestion avoidance is implemented inside a new action for a filter.

The code was developed using Linux kernel version *6.5.0-14-generic*.

# Requirements

Update the tc comandline program with the new qdisc and action:

```
cd iproute2
sudo make install
```

# Configuration

Change parameters in the kernel modules

### Qdisc (sch_ud_qos.c)

For example to set the threshold for the highest priority class:

```
q->thresholds[0] = 12500; # in line 468
```

### Filter Action (act_ud_qos.c)

For example to adjust the number of classes, the threshold for the highest priority class and the drop probability:

```
#define NUMBER_CLASSES 3 # in line 30
ud_qos.thresholds[0] = 250000; # in line 498
ud_qos.dropProbability[0] = 0; # in line 501
```

# Build and Start

First define the interface where UD-QoS should be set in the *add.sh*.
To build and add the UD-QoS to the interface run the following command:

```
sudo ./add.sh
```

The currently released monitoring uses a simplified version where each packet size is stored per IP. We are still polishing the sliding window version and will release it shortly.