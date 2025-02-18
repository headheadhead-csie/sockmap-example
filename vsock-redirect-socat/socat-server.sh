#!/bin/bash

usage() {
    echo "Usage: $0 <tcp port> <vsock cid> <vsock port> "
}

if [[ $# -ne 3 ]]; then
    usage
    exit
fi

TCP_PORT=$1
VSOCK_CID=$2
VSOCK_PORT=$3

socat TCP-LISTEN:${TCP_PORT} VSOCK-CONNECT:${VSOCK_CID}:${VSOCK_PORT}
