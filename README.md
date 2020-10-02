<p align="center"><img src="https://cs.piosky.fr/wifi/rogue_mana/trap.files/trap_transparent.png" alt="TRAP" width="270"/></p>

## Overview
TRAP (Targeted Rogue Access Point) is a tool for conducting 802.11 pentests and red team engagements. It is designed to create high-throughput rogue access points providing Internet access to vicitims.
Based on the specified channel, it chooses between 2.4GHz and 5Ghz spectrums and performs a 802.11n or 802.11ac rogue access point attack.

It can be further used for customized MiTM attacks via captive portal phishing.

## Features

- Two instances of TRAP at the same time
- 802.11n and 802.1ac
- Support for high-throughput, channel bonding, short GI, WMM, DFS, TPC...
- Support for open, WPA2-PSK and WPA2-EAP networks
- Internet access for supplicants
- Captive portal attacks (with SSL supportand phishing scenario based on user-agent)
- Steal 802.1x credentials (SSLv3 compatible) and loot file
- GTC downgrade attacks
- Support successful 802.1x authentication
- MANA attack on 2.4GHz only with internet access and MiTM possibilities
- Known beacon attack
- Management frame ACL based on BSSID (with wildcard support) and ESSID

## Documentation
The documentation is available [here](https://cs.piosky.fr/wifi/rogue_mana/trap/).

## Acknowledgments
TRAP uses, is based on or is inspired by the work of the following people:

- @s0lst1c3 (TRAP is based on hostapd-eaphammer)
- @singe
- @iandvl
- @_cablethief
- @W00Tock
- @vanhoefm
- @brad_anton
- @joswr1ght
- Jouni Malinen
- George Chatzisofroniou
- Robin Wood
- Dino Dai Zovi (@dinodaizovi)
- Shane Macaulay

## Licence
This project is [licensed](https://github.com/Piosky/TRAP/blob/master/LICENSE) under BSD 3-clause.

