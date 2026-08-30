#!/bin/sh
set -eu

OVPN=/vpn/operator.ovpn
AUTH=/vpn/operator.auth

fail() { printf '%s\n' "VPN sidecar failed closed" >&2; exit 1; }
[ -r "$OVPN" ] && [ -r "$AUTH" ] || fail

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
iptables -A OUTPUT -d 127.0.0.11 -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -d 127.0.0.11 -p tcp --dport 53 -j ACCEPT

awk '$1 == "remote" && $2 !~ /^#/ { print $2, ($3 ~ /^[0-9]+$/ ? $3 : 1198), ($4 == "tcp" || $4 == "tcp-client" ? "tcp" : "udp") }' "$OVPN" |
while read -r host port protocol; do
    getent ahostsv4 "$host" | awk '!seen[$1]++ {print $1}' |
    while read -r address; do
        iptables -A OUTPUT -o eth0 -d "$address" -p "$protocol" --dport "$port" -j ACCEPT
    done
done

# The up script replaces the provisional rules only after tun0 exists. Reject
# private, loopback, link-local, CGNAT, multicast, reserved, and metadata ranges
# before accepting other traffic on tun0. This applies to scanner redirects and
# browser subresources as well as the initial URL.
cat >/run/vpn-up <<'EOF'
#!/bin/sh
set -eu
iptables -F OUTPUT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for network in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
    iptables -A OUTPUT -d "$network" -j REJECT
done
iptables -A OUTPUT -d 169.254.169.254/32 -j REJECT
iptables -A OUTPUT -o tun0 -j ACCEPT
EOF
chmod 0500 /run/vpn-up

exec openvpn --config "$OVPN" --auth-user-pass "$AUTH" --auth-nocache \
    --script-security 2 --up /run/vpn-up --up-restart
