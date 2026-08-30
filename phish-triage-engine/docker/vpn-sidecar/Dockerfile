FROM alpine:3.21.7@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS openvpn-build

ARG OPENVPN_VERSION=2.6.22
ARG OPENVPN_SHA256=f46df740f05f86020137a41cfc8814352391cf861ed57f57b4e815cb97c1d2cf
ARG TUNNELBLICK_COMMIT=c9c73dca6c99afbba14b53e291b18f044210a1b5

RUN apk add --no-cache build-base curl libcap-ng-dev linux-headers lz4-dev lzo-dev openssl-dev && \
    mkdir /build && cd /build && \
    curl -fsSLo openvpn.tar.gz "https://swupdate.openvpn.org/community/releases/openvpn-${OPENVPN_VERSION}.tar.gz" && \
    echo "${OPENVPN_SHA256}  openvpn.tar.gz" | sha256sum -c - && \
    tar -xzf openvpn.tar.gz && cd "openvpn-${OPENVPN_VERSION}" && \
    for patch_number in 02 03 04 05 06; do \
      curl -fsSLo "/build/${patch_number}.diff" \
        "https://raw.githubusercontent.com/Tunnelblick/Tunnelblick/${TUNNELBLICK_COMMIT}/third_party/sources/openvpn/openvpn-${OPENVPN_VERSION}/patches/${patch_number}-tunnelblick-openvpn_xorpatch-$(echo abcde | cut -c $((patch_number - 1))).diff"; \
      patch -p1 < "/build/${patch_number}.diff"; \
    done && \
    ./configure --prefix=/usr --disable-debug --disable-dco --disable-plugin-auth-pam && \
    make -j2 && make DESTDIR=/stage install

FROM alpine:3.21.7@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

RUN apk add --no-cache \
      bind-tools=9.18.49-r0 \
      ca-certificates=20260413-r0 \
      curl=8.14.1-r2 \
      iproute2=6.11.0-r0 \
      iptables=1.8.11-r1 \
      libcap-ng=0.8.5-r0 \
      libcrypto3=3.3.7-r0 \
      libssl3=3.3.7-r0 \
      lz4-libs=1.10.0-r0 \
      lzo=2.10-r5

COPY --from=openvpn-build /stage/usr/sbin/openvpn /usr/sbin/openvpn

COPY entrypoint.sh /usr/local/sbin/vpn-entrypoint
COPY prepare-config.sh /usr/local/sbin/vpn-prepare-config
COPY pin-remotes.sh /usr/local/sbin/vpn-pin-remotes
COPY up.sh /usr/local/sbin/vpn-up
COPY healthcheck.sh /usr/local/sbin/vpn-healthcheck
COPY egress-check.sh /usr/local/sbin/vpn-egress-check
RUN chmod 0555 /usr/local/sbin/vpn-entrypoint /usr/local/sbin/vpn-prepare-config \
      /usr/local/sbin/vpn-pin-remotes /usr/local/sbin/vpn-up /usr/local/sbin/vpn-healthcheck \
      /usr/local/sbin/vpn-egress-check

ENTRYPOINT ["/usr/local/sbin/vpn-entrypoint"]
