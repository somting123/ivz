3 Gateway configuration

1) iptables --policy INPUT/OUTPUT DROP 

2) iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
3) iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
4) iptables --policy FORWARD ACCEPT

5) iptables -A OUTPUT -p icmp --icmp-type echo-reply -m state --state NEW (Dodamo še established in related?)
6) iptables -A OUTPUT -p udp -m multiport --dports 53,1812,1813,1814 -m state --state NEW -j ACCEPT (Dodamo še established in related?)

7) iptables -A INPUT -p icmp --icmp-type echo-request -m state --state NEW (Isto vpr?)
8) iptables -A INPUT -p udp -m multiport --dports 500,4500,4510,4511 -m state --state NEW -j ACCEPT (Isto vpr?)
