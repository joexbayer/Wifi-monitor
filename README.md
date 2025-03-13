# Wifi-Monitor

Experimental toy program to monitor wifi networks using a WiFi adapter in monitor mode.

## Requirements

Linux (Debian), C, Make, ncurses, iw and a wifi adapter that is able to go into monitor mode.

```bash
sudo apt install build-essential
sudo apt install libncurses-dev
sudo apt install iw
```

## Set WiFi adapter to monitor 

Simply use the setup.sh script. It needs the adapter interface name which can be fined with 
```bash
ip link
```

