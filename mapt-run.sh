#!/bin/bash
# ############################################################################## #
# Title: mapt-run                                                                #
# Author: d3adc0de                                                               #
# Description:                                                                   #
# This tool is designed to ease the setup of a wifi hosted-network to be used    #
# as a hotspot for mobile devices or IoT devices under testing.                  #
#                                                                                #
# The tools offers a recipe to redirect all the traffic to a specific interface  #
# or to redirect specific IP/Traffic to REDSOCKS to be forwarded to a mitm Proxy #
# as BurpSuite.                                                                  #
#                                                                                #
# Licence: MIT                                                                   #
# ############################################################################## #
# Permission is hereby granted, free of charge, to any person obtaining a copy   #
# of this software and associated documentation files (the "Software"), to deal  # 
# in the Software without restriction, including without limitation the rights   # 
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      # 
# copies of the Software, and to permit persons to whom the Software is          #  
# furnished to do so, subject to the following conditions:                       # 
# The above copyright notice and this permission notice shall be included in all #  
# copies or substantial portions of the Software.                                # 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     # 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       # 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    # 
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         # 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  # 
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  # 
# SOFTWARE.                                                                      # 
# ############################################################################## #

generateall(){
        
    HSconf="./hotspot.conf"
    HostaPDconf="./hostapd.conf"
    DNSmasqconf="./dnsmasq.conf"
    RSconf="./redsocks.conf"
    
    wlan="$1"
    ssid="$2"
    pass="$3"
    burpIP="$4"
    burp_port="$5"

    
    write_redsocks "$RSconf" "$burpIP" "$burp_port"
    write_hostapd "$HostaPDconf" "$wlan" "$ssid" "$pass"
    write_dnsmasq "$DNSmasqconf" "$wlan"
    write_hotspotconf "$HSconf" "$ssid" "$pass"
}

write_redsocks(){

    conf="$1"
    proxy_ip="$2"
    proxy_port="$3"
    echo "base {
    log_debug = on;
    log_info = on;
    log = \"file:/var/log/redsocks/redsocks.log\";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = \"0.0.0.0\";
    local_port = \"12345\";
    ip = \"$proxy_ip\";
    port = \"$proxy_port\";
    type = \"http-connect\";
}" > "$conf"                         
}

write_hostapd(){
    # hostapd.conf
    conf="$1"
    wlan="$2"
    ssid="$3"
    passphrase="$4"

    echo "# Define interface
interface=$wlan
# Select driver
driver=nl80211
# Set access point name
ssid=$ssid
# Set access point harware mode to 802.11g
hw_mode=g
# Set WIFI channel (can be easily changed)
channel=11
# Enable WPA2 only (1 for WPA, 2 for WPA2, 3 for WPA + WPA2)
wpa=2
wpa_passphrase=$passphrase" > "$conf"
}

write_dnsmasq(){
    # dnsmasq.conf
    conf="$1"
    wlan="$2"
    echo "# Bind to only one interface
bind-interfaces
# Choose interface for binding
interface=$wlan
# Specify range of IP addresses for DHCP leasses
# dhcp-range=172.0.0.10,172.0.0.250,8h
# Router
# dhcp-option=3,172.0.0.1
# DNS local
dhcp-option=6,172.0.0.1
# Specify global DNS server
server=8.8.8.8
server=8.8.4.4" > "$conf"

}

write_hotspotconf(){
    # hotspot.conf
    conf="$1"
    ssid="$2"
    passphrase="$3"

    echo "ctrl_interface=DIR=/run/wpa_supplicant GROUP=wheel
# use 'ap_scan=2' on all devices connected to the network
# this is unnecessary if you only want the network to be created when no other networks are available
ap_scan=1

network={
    ssid=\"$ssid\"
    mode=1
    frequency=2432
    proto=RSN
    key_mgmt=WPA-PSK
    pairwise=CCMP
    group=CCMP
    psk=\"$passphrase\"
}
" > "$conf"
}

run_redsocks(){
    # redsocks.conf
    conf="$1"
    mkdir -p "/var/log/redsocks"
    touch "/var/log/redsocks/redsocks.log"
    
    redsocks -c "$conf" 
}

run_hotspot(){
    # hotspot.conf
    conf="$1"
    wlan="$2"
    
    wpa_supplicant -B -i "$wlan" -c "$conf" -D nl80211,wext 
}

run_dnsmasq(){
    # dnsmasq.conf
    conf="$1"
        
    dnsmasq -C "$conf" 
}


run_hostapd(){
    # hostapd.conf
    conf="$1"
    wlan="$2"
    wired="$3"
    
    # Configure IP address for WLAN
    ifconfig $wlan 172.0.0.1 
    # Start DHCP/DNS server (Not needed as we are using dnsmasq)
    # kill -9 `cat /var/run/dhcpd.pid` 2>/dev/null
    # dhcpd 
    # systemctl restart dnsmasq
    # Enable routing
    sysctl net.ipv4.ip_forward=1 
    # Enable NAT
    iptables -t nat -A POSTROUTING -o $wired -j MASQUERADE 
    # Run access point daemon
    hostapd hostapd.conf 

}

init_iptables_redsocks(){
    
    wlan="$1"
        
    #### Packet marking for redirection
    #
    # ip rule add fwmark 2 table 3
    # ip route add default via 10.0.0.1 table 3
    # ip route flush cache

    #### Redirect https to dedicated interface (VPN)
    # 
    # iptables -t mangle -A OUTPUT -p tcp --dport 443 -j MARK --set-mark 2
    # iptables -t nat -A POSTROUTING -o tun1 -j SNAT --to-source 10.0.0.2

    #### Enable tun1 to receive marked packtes
    #sysctl -w net.ipv4.conf.tun1.rp_filter=2

    iptables -t nat -N REDSOCKS 
    
    # Create chain for VPN, if needed
    #iptables -t nat -N VPN

    #### Ignore LANs and reserved ranges
    iptables -t nat -A REDSOCKS -d 0.0.0.0/8 -j RETURN 
    iptables -t nat -A REDSOCKS -d 10.0.0.0/8 -j RETURN 
    iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN 
    iptables -t nat -A REDSOCKS -d 169.254.0.0/16 -j RETURN 
    iptables -t nat -A REDSOCKS -d 172.16.0.0/12 -j RETURN 
    iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN 
    iptables -t nat -A REDSOCKS -d 224.0.0.0/4 -j RETURN 
    iptables -t nat -A REDSOCKS -d 240.0.0.0/4 -j RETURN 

    #### VPN dedicated Chain, enable if needed
    # iptables -t nat -A PREROUTING -d 149.154.0.0/16 -j VPN

    #### Redirect VPN to FULL TRANSPARENT PROXY
    # iptables -t nat -A VPN -p tcp -j REDIRECT --to-ports 9999
     
    #### Redirect everything else to 12345
    iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345 
    iptables -t nat -A REDSOCKS -p udp -j REDIRECT --to-ports 12345 
    iptables -t nat -A REDSOCKS -p sctp -j REDIRECT --to-ports 12345 
    iptables -t nat -A REDSOCKS -p dccp -j REDIRECT --to-ports 12345 

    iptables -t nat -A PREROUTING --in-interface "$wlan" -j REDSOCKS 

}

init_selective_redirect(){

    #### Destination selection: useful for particular MApp

    # redsocks.conf
    wlan="$1"
    toRedirect=($(echo "$2" | awk -F"," '{for(i=1;i<=NF;i++){printf $i" " }}'))
        
    for ip in "${toRedirect[@]}"
    do
    if [[ "$(echo $ip | grep -oP '^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$')" == "" ]]; then
        echo "[-] Not valid IP: $ip"
        continue
    fi
    printf "[*] Redirecting $ip to redsocks... "
    iptables -t nat -A REDSOCKS -p tcp -d "$ip" -j REDIRECT --to-ports 12345 
    echo "Done"
    done

}

validate_ip(){
    ip="$1"
    if [[ "$(echo $ip | grep -oP '^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$')" == "" ]]; then
        echo "0"
    else
        echo "1"
    fi
}

validate_port(){
    port="$1"
    if [[ "$(echo $port | grep -oP '^\d{2,5}$')" == "" ]]; then
        echo "0"
    else
        echo "1"
    fi
}

runall(){
    HSconf="./hotspot.conf"
    HostaPDconf="./hostapd.conf"
    DNSmasqconf="./dnsmasq.conf"
    RSconf="./redsocks.conf"
    
    wlan="$1"
    wired="$2"
    ssid="$3"
    pass="$4"
        
    run_redsocks "$RSconf" 
    run_dnsmasq  "$DNSmasqconf" 
    run_hostapd "$HostaPDconf" "$wlan" "$wired" 
    run_hotspot "$HSconf" "$wlan" "$passphrase" 
    

}

usage(){
    echo "# #################                  MAPT Easy-Setup Script                ################# #"
    echo "#                                                                                            #"
    echo "#   This script has been made to easily generate and setup the environment for a Mobile PT   #" 
    echo "#                                                                                            #"
    echo "# ========================================================================================== #"
    echo "#                                                                                            #"
    echo "#   Usage:                                                                                   #"
    echo "#     ./mapt-run -s <SSID> -p <PWD> -l <LAN> -w <WLAN> [Optional args]                       #"
    echo "#   Required arguments:                                                                      #"
    echo "#     -s: SSID for the hosted network                                                        #"
    echo "#     -w: WLAN interface                                                                     #"
    echo "#     -l: LAN interface (internet access)                                                    #"
    echo "#   Optional arguments:                                                                      #"
    echo "#     -p: Passphrase for the hosted network (default: Passw0rd!)                             #"
    echo "#     -g: generate configuration files for hostapd, dnsmasq and redsocks                     #"
    echo "#     -e: run hostapd, dnsmasq and redsocks (implies -g)                                     #"
    echo "#     -r: redirect given IP addresses (comma divided) to redsocks                            #"
    echo "#     -i: install dependencies                                                               #"
    echo "#     -F: flush iptables chains                                                              #"
    echo "#     -K: kill all processes involved                                                        #"
    echo "#     -X: custom proxy (IP:PORT) (default: 127.0.0.1:8080)                                   #"
    echo "#     -h: show this help                                                                     #"
    echo "#                                                                                            #"
    echo "# ========================================================================================== #"
    exit 0
}

install(){
    apt-get update
    apt-get install -y hostapd redsocks dnsmasq dhcpd
}


default_passphrase="Passw0rd!"
init_redirection=0
generate=0
execute=0
flush_iptables=0
kill_processes=0
proxy_ip="127.0.0.1"
proxy_port=8080

if [ $(id -u) -gt 0 ]; then
    echo "[-] Must run as root or sudo"
    exit 1
fi

if [ $# -lt 1 ]; then
    usage
fi

while (( "$#" )); do
    case "$1" in
        -h|--help)
            usage
            break
            ;;
        -s|--ssid)
            ssid="$2"
            shift 2
            ;;
        -w|--wlan)
            wlan_iface="$2"
            shift 2
            ;;
        -l|--wired)
            wired_iface="$2"
            shift 2
            ;;
        -i|--install)
            install
            exit 0
            ;;
        -p|--passphrase)
            passphrase="$2"
            shift 2
            ;;
        -g|--generate)
            generate=1
            shift 1
            ;;
        -e|--execute)
            execute=1
            shift 1
            ;;
        -F|--flush)
            flush_iptables=1
            shift 1
            ;;
        -k|--killall)
            kill_processes=1
            shift 1
            ;;
        -r|--redirect)
            redirect="$2"
            shift 2
            ;;
        -X|--proxy)
            proxy_ip=$(echo "$2" | awk -F":" '{print $1}')
            if [ "$(validate_ip $proxy_ip)" -eq 0 ]; then
                echo "[-] Invalid proxy address: $proxy_ip"
                exit 1
            fi
            proxy_port=$(echo "$2" | awk -F":" '{print $2}')
            if [ "$(validate_port $proxy_port)" -eq 0 ]; then
                echo "[-] Invalid proxy port: $proxy_port"
                exit 1
            fi
            shift 2
            ;;
        --) # end argument parsing
            shift
            break
            ;;
        -*|--*) # unsupported flags
            echo  "Error: Unsupported flag $1" >&2
            exit 1
            ;;
        *) # preserve positional arguments
            if [ -n "$PARAMS" ]
                then
                PARAMS="$1"
            fi
            shift
            ;;
    esac
done

# set positional arguments in their proper place (Not used)
eval set -- "$PARAMS"

if [ $flush_iptables -gt 0 ]; then
    printf "[+] Flushing IPTABLES... "
    iptables -t nat -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -F 2>/dev/null
    echo "Done"
fi

if [ $kill_processes -gt 0 ]; then
    for p in hostapd dnsmasq redsocks
    do
        printf "[+] Killing $p... "
        killall $p 2>/dev/null
        echo "Done"
    done
fi

if [ -z $ssid ] || [ -z $wlan_iface ] || [ -z $wired_iface ]; then
    echo "[-] SSID, WLAN and LAN are required to setup the hosted network"
    usage
    exit 1
fi

if [ -z $passphrase ]; then
    passphrase=$default_passphrase
    echo "[*] No passphrase provided, using default: $passphrase"
fi

if [ $generate -eq 0 ] && [ $execute -eq 0 ]; then
    echo "[-] Generate flag not set"
    echo "[-] Execute flag not set"
    echo "[-] Aborting"
    exit 1
fi

if [ -n $redirect ]; then
    if [[ "${redirect: -1}" == ","  ]]; then
        echo "[-] Potential error detected with -r"
        echo "[-] Remeber that IP Addresses should be provided comma separated without any space"
        echo "[-] Current redirect string: $redirect"
        exit 1
    else
        init_redirection=1
    fi
fi

if [ $generate -gt 0 ] || [ $execute -gt 0 ]; then
    echo "[*] Generating configuration files"
    generateall "$wlan_iface" "$ssid" "$passphrase" "$proxy_ip" "$proxy_port"
fi

if [ $execute -gt 0 ]; then
    
    if [ $init_redirection -gt 0 ]; then
        printf "[*] Setting up iptables for redsocks... "
        init_iptables_redsocks "$wlan_iface"     
        init_selective_redirect "$wlan_iface" "$redirect"     
        echo "Done"
    fi    
    printf "[*] Spinning up redsocks, dnsmasq and hostapd... "
    runall "$wlan_iface" "$wired_iface" "$ssid" "$passphrase"     
    echo "Done"
else
    echo "[+] Done"
fi

