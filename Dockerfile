# =========================================================================
# STAGE 1: Toolchain Build Engine (Compiling Matched Host Utilities)
# =========================================================================
FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git build-essential bison flex libelf-dev libmnl-dev \
    clang llvm pkg-config libcap-dev libreadline-dev libdb-dev libssl-dev wget

# HOST ALIGNMENT 1: Clone and compile iproute2-6.19.0
RUN git clone --depth 1 --branch v6.19.0 https://git.kernel.org/pub/scm/network/iproute2/iproute2.git /src/iproute2
WORKDIR /src/iproute2
RUN ./configure && make && make install

# HOST ALIGNMENT 2: Clone and compile bpftool v7.7.0 (via upstream kernel tree)
RUN git clone --depth 1 https://github.com/torvalds/linux.git /src/linux
WORKDIR /src/linux/tools/bpf/bpftool
RUN make && cp bpftool /usr/local/sbin/bpftool

# =========================================================================
# STAGE 2: Core Sovereign Node Fabric (Your Cleaned Production Layer)
# =========================================================================
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# 🟢 FIXED: Added libbpf-dev here to restore /usr/include/bpf/ files permanently
RUN apt-get update && apt-get install -y \
    iputils-ping ethtool tcpdump pciutils \
    build-essential clang llvm m4 \
    linux-headers-generic linux-tools-common linux-tools-generic \
    jq curl telnet gpg iptables kmod ca-certificates \
    iperf3 traceroute mtr lsb-release gnupg2 \
    libelf1 libmnl0 libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# Now curl is 100% available to download the authentication keys
RUN mkdir -p /etc/apt/keyrings && \
    curl -s https://deb.frrouting.org/frr/keys.asc | gpg --dearmor -o /etc/apt/keyrings/frr.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/frr.gpg] https://deb.frrouting.org/frr noble frr-9" > /etc/apt/sources.list.d/frr.list && \
    apt-get update && apt-get install -y frr frr-pythontools

# Configure FRR Daemons exactly to your specifications
RUN sed -i 's/bgpd=yes/bgpd=no/g' /etc/frr/daemons && \
    sed -i 's/isisd=no/isisd=yes/g' /etc/frr/daemons && \
    sed -i 's/pathd=no/pathd=yes/g' /etc/frr/daemons

RUN mkdir -p /sys/fs/bpf

# INJECT HOST-ALIGNED BINARY ENGINE ASSETS
COPY --from=builder /usr/sbin/ip /usr/sbin/ip
COPY --from=builder /usr/local/sbin/bpftool /usr/sbin/bpftool

# 控制面大腦與協議棧的唯一發動機
CMD ["bash", "-c", "/usr/lib/frr/frrinit.sh start && tail -f /dev/null"]
