FROM ubuntu:26.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl3 libsodium23 libc-ares2 zlib1g libzstd1 libgcc-s1 \
      wireguard-tools iproute2 iputils-ping ca-certificates python3 libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
COPY lib/ /usr/local/lib/
RUN ldconfig
COPY wg-punch /usr/local/bin/wg-punch
COPY wireguard-go /opt/vpn/bin/wireguard-go
COPY vpn /opt/vpn/vpn
COPY httpd.py /httpd.py
COPY entry.sh /entry.sh
RUN (cp /usr/sbin/capsh /opt/vpn/bin/capsh 2>/dev/null || cp /usr/bin/capsh /opt/vpn/bin/capsh) \
    && chmod +x /entry.sh /opt/vpn/vpn /usr/local/bin/wg-punch /opt/vpn/bin/*
ENV LD_LIBRARY_PATH=/usr/local/lib
ENTRYPOINT ["/entry.sh"]
