#!/bin/bash

INTERFACE_NAME="wlx9cefd5fcd6a8"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

sudo ip link set dev $INTERFACE_NAME down
sudo iw $INTERFACE_NAME set monitor none
sudo ip link set dev $INTERFACE_NAME up
iw $INTERFACE_NAME info | grep 'type'
