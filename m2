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
==========================================================================
2) Radius server
NETPLAN
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [172.16.0.2/16]
      routes:
        - to: default
          via: 172.16.0.1
      nameservers:
        addresses: [8.8.8.8]

sudo nano /etc/freeradius/3.0/clients.conf
client router {
        ipaddr = 172.16.0.1
        secret = radiuspassword
        require_message_authenticator = no
        nas_type = other 
}

sudo nano /etc/freeradius/3.0/users (dodaj userja in password)
 
STOP service:
 sudo service freeradius stop
START the server
 sudo freeradius -X -d /etc/freeradius/3.0
TEST service
echo "User-Name=alice, User-Password=password" | radclient 127.0.0.1 auth testing123 -x




===========================================================================
3 Gateway configuration

1)sudo iptables --policy INPUT/OUTPUT DROP 

2)sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
3)sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
4)sudo iptables --policy FORWARD ACCEPT

5)sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -m state --state NEW (Dodamo še established in related?)
6)sudo iptables -A OUTPUT -p udp -m multiport --dports 53,1812,1813,1814 -m state --state NEW -j ACCEPT (Dodamo še established in related?)

7)sudo iptables -A INPUT -p icmp --icmp-type echo-request -m state --state NEW (Isto vpr?)
8)sudo iptables -A INPUT -p udp -m multiport --dports 500,4500,4510,4511 -m state --state NEW -j ACCEPT (Isto vpr?)
========================================================================================
4 Gateway VPN configuration
nano /etc/ipsec.conf

config setup
        # strictcrlpolicy=yes
        # uniqueids = no
conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        authby=secret

conn net-net
        leftsubnet=172.16.1.0/24
        leftfirewall=yes
        leftid=gw
        right=0.0.0.0/0
        right=@outsideworld
        auto=add
20%:
sudo nano /etc/ipsec.secrets
gw @outsideworld : PSK "mypsk"
