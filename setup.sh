#!/bin/bash
sudo ethtool -L enp8s0f0 combined 8
echo 256 | sudo tee /sys/class/net/enp8s0f0/busy_budget
echo 2 | sudo tee /sys/class/net/enp8s0f0/napi_defer_hard_irqs
echo 200000 | sudo tee /sys/class/net/enp8s0f0/gro_flush_timeout