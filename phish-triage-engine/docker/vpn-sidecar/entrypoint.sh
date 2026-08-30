#!/bin/sh
set -eu

OVPN=/vpn/operator.ovpn
AUTH=/vpn/operator.auth
RUNTIME_OVPN=/run/operator.runtime.ovpn

fail() { printf '%s\n' "VPN sidecar failed closed" >&2; exit 1; }
[ -r "$OVPN" ] && [ -r "$AUTH" ] || fail
/usr/local/sbin/vpn-prepare-config "$OVPN" "$RUNTIME_OVPN" || fail
/usr/local/sbin/vpn-pin-remotes "$RUNTIME_OVPN" || fail

# Install DROP policies before resolving or starting OpenVPN. Docker's embedded
# DNS is the sole pre-tunnel DNS exception; resolved VPN endpoints are the sole
# non-tunnel egress exception.
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
awk '$1 == "remote" && $2 !~ /^#/ { print $2, ($3 ~ /^[0-9]+$/ ? $3 : 1198), ($4 == "tcp" || $4 == "tcp-client" ? "tcp" : "udp") }' "$RUNTIME_OVPN" |
while read -r host port protocol; do
    iptables -A OUTPUT -o eth0 -d "$host" -p "$protocol" --dport "$port" -j ACCEPT
done

# The up script replaces the provisional rules only after tun0 exists. Reject
# private, loopback, link-local, CGNAT, multicast, reserved, and metadata ranges
# before accepting other traffic on tun0. This applies to scanner redirects and
# browser subresources as well as the initial URL.
exec openvpn --config "$RUNTIME_OVPN" --auth-user-pass "$AUTH" --auth-nocache \
    --script-security 2 --up /usr/local/sbin/vpn-up --up-restart
