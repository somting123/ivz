# *** EXAMPLE MIDTERM 2 ***

#2x computers with NAT network and private network adapters 
#namescanje paketov
sudo apt update
sudo apt install strongswan strongswan-pki libcharon-extra-plugins apache2 wireshark openssh-server openssh-client

## VPN
# hq server:
sudo nano /etc/netplan/01-network-manager-all.yaml
#content
    network:
    version: 2
    ethernets:
        enp0s3:
        dhcp4: true
        dhcp-identifier: mac
        enp0s8:
        addresses: [10.1.0.1/16]

sudo netplan apply

# br client:
sudo nano /etc/netplan/01-network-manager-all.yaml
#content
    network:
    version: 2
    ethernets:
        enp0s3:
        dhcp4: true
        dhcp-identifier: mac
        enp0s8:
        addresses: [10.2.0.1/16]

sudo netplan apply

# hq server
sudo nano /etc/ipsec.conf
#content
    config setup

    conn %default
            ikelifetime=60m
            keylife=20m
            rekeymargin=3m
            keyingtries=1
            keyexchange=ikev2
            authby=secret

    conn net-net
            leftsubnet=10.1.0.0/16
            leftfirewall=yes
            leftid=@hq
            right=10.0.2.12
            rightsubnet=10.2.0.0/16
            rightid=@branch
            auto=add

sudo nano /etc/ipsec.secrets
# content
    @hq @branch : PSK "this_is_my_psk"

sudo ipsec restart


# br client
sudo nano /etc/ipsec.conf

#content
    config setup

    conn %default
            ikelifetime=60m
            keylife=20m
            rekeymargin=3m
            keyingtries=1
            keyexchange=ikev2
            authby=secret

    conn net-net
            leftsubnet=10.2.0.0/16
            leftid=@branch
            leftfirewall=yes
            right=10.0.2.11
            rightsubnet=10.1.0.0/16
            rightid=@hq
            auto=add

sudo nano /etc/ipsec.secrets
# content
    @hq @branch : PSK "this_is_my_psk"

sudo ipsec restart

# br client
sudo ipsec up net-net


## SSH

# hq server 

/etc/hosts
# content
    127.0.1.1 hq

sudo hostnamectl set-hostname hq

sudo ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key


# br client
ssh isp@10.0.2.11

exit

ssh-keygen -t ecdsa

ssh-copy-id isp@10.0.2.11

# hq server
sudo nano /etc/ssh/sshd_config
#content
    PasswordAuthentication no

sudo service ssh restart

## FIREWALL

sudo nano handson-tables.sh
#content add
    # ESTABLISHED, RELATED
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # VPN
    iptables -A INPUT -p udp -m multiport --ports 500,4500 -m state --state NEW -j ACCEPT
    iptables -A OUTPUT -p udp -m multiport --ports 500,4500 -m state --state NEW -j ACCEPT

    iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

    iptables -A INPUT -p esp -m state --state NEW -j ACCEPT
    iptables -A INPUT -p ah -m state --state NEW -j ACCEPT

    # ICMP
    iptables -A OUTPUT -p icmp -m state --state NEW -j ACCEPT
    iptables -A INPUT -p icmp -m state --state NEW -j ACCEPT

    # DNS server.
    iptables -A OUTPUT -o $INET_IFACE -p udp  --dport 53 -j ACCEPT


sudo ./handson-tables.sh restart

ssh 10.0.2.11
