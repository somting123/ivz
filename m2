1) Gateway setup
Adapter 1: NAT, A2: INT NET
sudo service systemd-networkd start
sudo nano /etc/netplan/01- (Tab)
(fajl):
  GNU nano 6.2        /etc/netplan/01-network-manager-all.yaml                  
# Let NetworkManager manage all devices on this system
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
      dhcp-identifier: mac
    enp0s8:
      addresses: [172.16.0.1/16]
      
  sudo netplan apply
  echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward



3 Gateway configuration

1)sudo iptables --policy INPUT/OUTPUT DROP 

2)sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
3)sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
4)sudo iptables --policy FORWARD ACCEPT

5)sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -m state --state NEW (Dodamo še established in related?)
6)sudo iptables -A OUTPUT -p udp -m multiport --dports 53,1812,1813,1814 -m state --state NEW -j ACCEPT (Dodamo še established in related?)

7)sudo iptables -A INPUT -p icmp --icmp-type echo-request -m state --state NEW (Isto vpr?)
8)sudo iptables -A INPUT -p udp -m multiport --dports 500,4500,4510,4511 -m state --state NEW -j ACCEPT (Isto vpr?)
