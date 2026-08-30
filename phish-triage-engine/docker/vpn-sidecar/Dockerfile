FROM alpine:3.21.7@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

RUN apk add --no-cache \
      bind-tools=9.18.49-r0 \
      ca-certificates=20260413-r0 \
      curl=8.14.1-r2 \
      iproute2=6.11.0-r0 \
      iptables=1.8.11-r1 \
      openvpn=2.6.20-r0

COPY entrypoint.sh /usr/local/sbin/vpn-entrypoint
COPY healthcheck.sh /usr/local/sbin/vpn-healthcheck
COPY egress-check.sh /usr/local/sbin/vpn-egress-check
RUN chmod 0555 /usr/local/sbin/vpn-entrypoint /usr/local/sbin/vpn-healthcheck \
      /usr/local/sbin/vpn-egress-check

ENTRYPOINT ["/usr/local/sbin/vpn-entrypoint"]
