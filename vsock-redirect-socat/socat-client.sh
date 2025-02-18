#!/bin/bash

usage() {
    echo "Usage: $0 <vsock port> <ip addr> <tcp port>"
}

if [[ $# -ne 3 ]]; then
    usage
    exit
fi

VSOCK_PORT=$1
IP_ADDR=$2
TCP_PORT=$3

socat VSOCK-LISTEN:$1 TCP:${IP_ADDR}:${TCP_PORT}
