#!/bin/sh
set -eu
test -d /sys/class/net/tun0
ip route get 1.1.1.1 | grep -q ' dev tun0 '
iptables -C OUTPUT -o tun0 -j ACCEPT
