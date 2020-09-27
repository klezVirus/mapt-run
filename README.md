# mapt-run

Simple script to setup a local hosted network for Mobile Application Penetration Testing

## Overview

It often happens, a the very beginning of a mobile penetration test, to spend a bit of time setting up a correct lab environment. If using a physical device, part of this setup usually consists of a few steps:

* configure a hotspot via hostapd
* setup dnsmasq for the hosted network
* setup redsocks to wrap socket connections for BurpSuite
* setup iptables to provide internet to the hosted network
* other iptables configuration

This script provides a good start into automating this process, providing a nice set of configurable options.

## Note

This script is far from being finished. A lot of options might be added in future.

## Usage

Using the script is simple, as observable by the help:

```
# #################                  MAPT Easy-Setup Script                ################# #
#                                                                                            #
#   This script has been made to easily generate and setup the environment for a Mobile PT   #
#                                                                                            #
# ========================================================================================== #
#                                                                                            #
#   Usage:                                                                                   #
#     ./mapt-run -s <SSID> -p <PWD> -l <LAN> -w <WLAN> [Optional args]                       #
#   Required arguments:                                                                      #
#     -s: SSID for the hosted network                                                        #
#     -w: WLAN interface                                                                     #
#     -l: LAN interface (internet access)                                                    #
#   Optional arguments:                                                                      #
#     -p: Passphrase for the hosted network (default: Passw0rd!)                             #
#     -g: generate configuration files for hostapd, dnsmasq and redsocks                     #
#     -e: run hostapd, dnsmasq and redsocks (implies -g)                                     #
#     -r: redirect given IP addresses (comma divided) to redsocks                            #
#     -i: install dependencies                                                               #
#     -F: flush iptables chains                                                              #
#     -K: kill all processes involved                                                        #
#     -X: custom proxy (IP:PORT) (default: 127.0.0.1:8080)                                   #
#     -h: show this help                                                                     #
#                                                                                            #
# ========================================================================================== #
```

## Further work

* Enable VPN redirection
* Redsocks port customisation
* Many others
