# Wifi-Monitor

Experimental toy program to monitor wifi networks using a WiFi adapter in monitor mode. Developed to find and detect faulty access points by failed and retried frames.

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

## Legal

Most countries prohibit intercepting Wi-Fi traffic without the user’s consent.

<p align="center">
  <img src="https://github.com/joexbayer/Wifi-monitor/blob/main/imgs/aps.png?raw=true">
</p>

<p align="center">
  <img src="https://github.com/joexbayer/Wifi-monitor/blob/main/imgs/clients.png?raw=true">
</p>

<p align="center">
  <img src="https://github.com/joexbayer/Wifi-monitor/blob/main/imgs/networks.png?raw=true">
</p>