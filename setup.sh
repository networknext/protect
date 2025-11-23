#!/bin/bash

sudo ethtool -L eth0 combined 8
sudo bash -c "echo 0 > /sys/class/net/enp8s0f0/napi_defer_hard_irqs"
sudo bash -c "echo 0 > /sys/class/net/enp8s0f0/gro_flush_timeout"
