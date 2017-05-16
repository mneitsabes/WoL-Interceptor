The WoL request doesn't pass the fiwall/router. The goal of this script is to catch the WoL packet and relaying them to a relay.

# Config

You must edit the file :

* <code>wolinterceptor-server.py</code> : to set the parameters

Create the log file and allow the user to write to it :

* <code>touch path_to_log && chown user:user path_to_log</code>

# Firewall

Allow incoming WoL magic packet to broadcast

* <code>iptables -A INPUT -i ethX -p udp -d 10.0.xxx.255 --dport 9 -j ACCEPT</code>

Allow outgoing WoL connections to the WoL Relay

* <code>iptables -A OUTPUT -o ethX -p tcp -d 10.0.xxx.yyy --dport 8000 -m state --state NEW,ESTABLISHED -j ACCEPT</code>
* <code>iptables -A INPUT  -i ethX -p tcp -s 10.0.xxx.yyy --sport 8000 -m state --state ESTABLISHED,RELATED -j ACCEPT</code>

# How does the web interface and the relay communicate ?

The protocol is based on 4 steps :

* The interceptor sends the MAC address of the computer to wake up with the format "XX:XX:XX:XX:XX:XX"
* The Python relay generates a challenge and sends it back to the web interface
* The interceptor computes the response of the challenge based on HMAC-SHA256 with a shared secret and sends back his response
* The Python relay checks the response and wakes up the computer
