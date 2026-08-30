FROM alpine:3.21.7@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

RUN apk add --no-cache \
      chromium=136.0.7103.113-r0 \
      python3=3.12.14-r0

COPY scanner.py /usr/local/bin/pte-scanner
RUN chmod 0555 /usr/local/bin/pte-scanner

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/pte-scanner"]
