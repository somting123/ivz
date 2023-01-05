# MIDTERM 2

## Table of contents
##### [0. Software install](#0)
##### [1. Stateless firewalls](#1)
##### [2. Stateful firewalls](#2)
##### [3. SSH Protocol](#3)
##### [4. VPN with IPsec](#4)
##### [5. AAA](#5)
#

## 0. Software install<a name="0"/>

`sudo apt update`\
\
`sudo apt install openssh-server openssh-client wireshark apache2 curl git dig strongswan strongswan-pki libcharon-extra-plugins freeradius freeradius-utils libapache2-mod-auth-radius`

## [1. Stateless firewalls](https://ucilnica.fri.uni-lj.si/mod/page/view.php?id=8650)<a name="1"/>

### [iptables1.sh](https://github.com/aklemen/midterm-2/blob/main/iptables1.sh)

### Software

`sudo apt-get install openssh-server apache2 curl git`\
`sudo make-ssl-cert generate-default-snakeoil --force-overwrite` - generate default digital certificates for Apache2\
`sudo a2ensite default-ssl` - enable Apache2 SSL Site\
`sudo a2enmod ssl` - enable Apache2 TLS/SSL module\
`sudo service apache2 restart` - restart Apache server

### Disable IPv6

Add to file with `sudo nano /etc/sysctl.conf`:

```
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

Activate changes with `sudo sysctl -p`.\
**! Run this command each time you start up the image.**

### Useful commands

`sudo tcpdump -i any icmp` - listen to pings\
`ip link` - show network interfaces\
`ip addr` - show machine's IPs\
`ping <IP/URL>` - ping given IP (test ICMP)\
`dig <URL>` - resolve IP of URL / domain (test DNS)\
`touch <filename>` - create new file at the current directory\
`ssh <IP>` - establish SSH connection with given IP (test SSH)\
`logout` or CTRL+D - terminate SSH connection\
`curl <URL>` - get page at URL (test HTTP)\
`curl -I <URL>` - get just headers at URL (test HTTP)\
`chmod +x <file>` - chane file's execution permissionsq

### [Iptables](https://wiki.ubuntu.org.cn/Quick_HOWTO_:_Ch14_:_Linux_Firewalls_Using_iptables)

`sudo iptables --list -nv` - show firewall rules\
`sudo <.sh file> restart` - apply the firewall rules from file, e.g. `./handson-tables.sh`\
`sudo <.sh file> reset` - reset firewall rules to default


### Stateless firewall rules
```bash
### SSH
# Allow outgoing SSH connections
iptables -A OUTPUT -p tcp         --dport 22 -j ACCEPT
iptables -A INPUT  -p tcp ! --syn --sport 22 -j ACCEPT
# Allow incoming SSH connections
iptables -A INPUT  -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

### HTTP
# Allow outgoing HTTP connections
iptables -A OUTPUT -p tcp         --dport 80 -j ACCEPT
# Allow incoming HTTP connections
iptables -A INPUT  -p tcp ! --syn --sport 80 -j ACCEPT

### HTTPS
# Allow outgoing HTTPS connections
iptables -A OUTPUT -p tcp         --dport 443 -j ACCEPT
# Allow incoming HTTPS connections
iptables -A INPUT  -p tcp ! --syn --sport 443 -j ACCEPT

### ICMP
# Allow outgoing ping requests (and corresponding ping replies)
# Allowing the ping requests, made from this machine
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
# Allowing the corresponding ping replies from the pinged server
iptables -A INPUT  -p icmp --icmp-type echo-reply   -j ACCEPT
# Allow incoming pings but only from a specific IP address
CHOSEN_IP="10.0.2.6"
iptables -A INPUT -p icmp -s $CHOSEN_IP -j ACCEPT
```

## [2. Stateful firewalls](https://ucilnica.fri.uni-lj.si/mod/page/view.php?id=8751)<a name="2"/>

### [iptables2.sh](https://github.com/aklemen/midterm-2/blob/main/iptables2.sh)

### Configure network intefaces
##### Router

Populate the file with `sudo nano /etc/netplan/01-network-manager-all.yaml`:
```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
      dhcp-identifier: mac
    enp0s8:
      addresses: [10.0.0.1/24]
    enp0s9:
      addresses: [172.16.0.1/24]
```
`sudo netplan apply` - apply the changes\
`echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward` - enable forwarding / routing\
`sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE` - configure to act as NAT

##### Client / Server

Populate the file with `sudo nano /etc/netplan/01-network-manager-all.yaml`:
```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      # assign the IP address
      addresses: [10.0.0.2/24] / [172.16.0.2/24]
      # set the default route through isp
      gateway4: 10.0.0.1 / 172.16.0.1
      # use Google's DNS
      nameservers:
        addresses: [8.8.8.8]
```
`sudo netplan apply` - apply the changes

### Stateful firewall rules
##### Input / output rules
#
```bash
# ESTABLISH-RELATED trick: Allow all incoming packets that belong to ESTABLISHED or RELATED connections.
iptables -A INPUT  -m state --state ESTABLISHED, RELATED -j ACCEPT
# From here onwards, we can add incoming firewall exceptions using only the NEW state

# Allow all outgoing packets that belong to ESTABLISHED or RELATED connections.
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow outgoing DNS requests to the DNS server in variable NAMESERVER
iptables -A OUTPUT -p udp -d $NAMESERVER --dport 53 -m state --state NEW -j ACCEPT

### SSH
# Allow outgoing SSH connections to remote SSH servers
#iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
# Allow incomming connections to local SSH server
#iptables -A INPUT  -p tcp --dport 22 -m state --state NEW -j ACCEPT

### HTTP
# Allow outgoing HTTP requests 
#iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
# Allow incoming HTTP requests destined to local HTTP server
#iptables -A INPUT  -p tcp --dport 80 -m state --state NEW -j ACCEPT

### HTTPS
# Allow outgoing HTTPS requests 
#iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT
# Allow incoming HTTPS requests destined to local HTTP server
#iptables -A INPUT  -p tcp --dport 443 -m state --state NEW -j ACCEPT

### ICMP
# Allow outgoing ping requests
iptables -A OUTPUT -p icmp --icmp-type echo-request -m state --state NEW -j ACCEPT
# Allow incoming ping requests
iptables -A INPUT  -p icmp --icmp-type echo-request -m state --state NEW -j ACCEPT
# Limit the number of ping requests to the firewall to 10 per minute when they come from the public Internet.
# Napisemo pred ukaza, ki sprejemata vse ESTABLISHED in REALTED povezave.
iptables -A OUTPUT -p icmp -m icmp --icmp-type echo-request -m limit --limit 10/minute -j ACCEPT
iptables -A OUTPUT -p icmp -j DROP

# Compressed rules using "-m multiport" and "--ports" switches.
iptables -A OUTPUT -p tcp -m multiport --ports 22,80,443 -m state --state NEW -j ACCEPT
iptables -A INPUT  -p tcp -m multiport --ports 22,80,443 -m state --state NEW -j ACCEPT

```
##### Forwarding rules
#
```bash
### NAT
# Do NAT for internet-bound traffic
iptables -t nat -A POSTROUTING -o $INET_IFACE -j MASQUERADE

# Allow routing of packets that belong to ESTABLISHED or RELATED connections.
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

### ICMP
# Forward pings
iptables -A FORWARD -p icmp --icmp-type echo-request -m state --state NEW  -j ACCEPT

### DNS
# Forward DNS requests from subnets to Internet and permit in corresponding responses
iptables -A FORWARD -o $INET_IFACE -p udp -m multiport --ports 53 -m state --state NEW -j ACCEPT

### HTTP, HTTPS, SSH
# Forward HTTP, HTTPS and SSH traffic from client_subnet to Internet and to server_subnet
#iptables -A FORWARD -p tcp -i enp0s8 -m multiport --ports 22,80,443 -m state --state NEW -j ACCEPT

# Allow all SSH connections between client_subnet and the server_subnet. Prevent SSH connections to the public Internet.
iptables -A FORWARD -i enp0s8 -o enp0s9 -p tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -A FORWARD -i enp0s9 -o enp0s8 -p tcp --dport 22 -m state --state NEW -j ACCEPT

# Prevent any access to facebook.com.
FB=$(dig +noall +answer facebook.com | cut -f6 | xargs | tr " " ,)
iptables -I FORWARD -d $FB -j DROP
```

## [3. SSH Protocol](https://ucilnica.fri.uni-lj.si/mod/page/view.php?id=8957)<a name="3"/>

### Change machine hostname

Add to file `sudo nano /etc/hosts`:\
`127.0.1.1 <name>`\
Run:\
`sudo hostnamectl set-hostname <name>`

### Regenerate **server's** SSH keys

`sudo ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key`\
`sudo ssh-keygen -t rsa   -f /etc/ssh/ssh_host_rsa_key`\
`sudo ssh-keygen -t dsa   -f /etc/ssh/ssh_host_dsa_key`\
`sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key`

### Check **server's** public key fingerprint

Depends on the one the server is using.\
`ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub`\
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`\
`ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub`\
`ssh-keygen -lf /etc/ssh/ssh_host_dsa_key.pub`

### Useful commands

`sudo nano /etc/ssh/sshd_config` - `HostKey` naming directive\
`sudo nano ~/.ssh/known_hosts` - remove saved fingerprints on client\
`ssh -i ~/.ssh/id_rsa <IP> -v` - connect with public key authentication\
`ssh-copy-id <IP>` - copy public key to chosen account and add to the authorized_keys list\
`ssh -o PreferredAuthentications=<password> -o PubkeyAuthentication=no <IP>` - test SSH connection with username-password authentication (explicitly)

### Regenerate **client's** SSH keys
Stored in `~/.ssh`.\
`ssh-keygen -t rsa`\
`ssh-keygen -t dsa`\
`ssh-keygen -t ecdsa`

### Disable password authentication
Add to file `sudo nano /etc/ssh/sshd_config`:\
`PasswordAuthentication no`\
Run:\
`sudo service ssh restart` - restart the SSH server

### SSH tunneling (**from client**)
##### Allow only localhost connections on Apache
Add to file `sudo nano /etc/apache2/sites-available/000-default.conf`:
```apache
<Directory /var/www/html>
    Require ip 127.0.0.1/8
</Directory>
```
`sudo service apache2 reload` - reload Apache configuration
##### Connect from client
`ssh -L 127.0.0.1:8080:127.0.0.1:80 -N <SERVER_IP>`\
`curl localhost:8080` - test\
`tail -f /var/log/apache2/access.log` - real-time Apache access log

### Reverse SSH tunneling (**from server**)

##### Prepare
Set firewall rules:
```
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT  -p tcp --dport 22 -m state --state NEW -j ACCEPT
```
Delete previously added content in `sudo nano /etc/apache2/sites-available/000-default.conf`.\
`sudo service apache2 reload` - reload Apache configuration

##### Connect from server
`ssh -R 127.0.0.1:8080:127.0.0.1:80 -N <CLIENT_IP>`

## [4. VPN with IPsec](https://ucilnica.fri.uni-lj.si/mod/page/view.php?id=9139)<a name="4"/>

See the assignment instructions for the setup of virtual machines.

### Create a VPN IPsec tunnel
##### Set-up machines
#
Configure file `sudo nano /etc/ipsec.conf`:
```
config setup

conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        authby=secret

conn net-net
        leftsubnet=<THIS machine's subnet, e.g. 10.1.0.0/16>
        leftfirewall=yes
        leftid=<THIS machine's name, e.g. @hq>
        right=<OTHER machine's IP, e.g. 10.2.0.2>
        rightsubnet=<OTHER machine's subnet, e.g. 10.2.0.0/16>
        rightid=<OTHER machine's name, e.g. @branch>
        auto=add
```
Add pre-shared key (PSK) to file `sudo nano /etc/ipsec.secrets`:
```sh
@hq @branch : PSK "secret"
```
Run:\
`sudo ipsec restart` - changes get loaded
##### Establish the VPN link

`sudo ipsec up net-net` - establish the tunnel\
`sudo ipsec status` - check status\
`sudo ipsec statusall` - check detailed status\
`sudo ipsec start --nofork` - run strongswan daemon in foreground (stops strongswan and terminates all VPN connections)\
`ping -I <FROM_IP> <TO_IP>` - ping from source to destination\
`sudo ipsec restart` - restart IPsec\
`tail -f -n 0 /var/log/auth.log` - observe IKE PHASE 1 (SA) and 2 (KE)\
`sudo ip xfrm policy` - observe ISAKMP populated Security Policy Database

##### Change encryption
To use AES_GCM_256, add to `/etc/ipsec.conf` on both machines:
```
ike=aes256gcm16
esp=aes256gcm16
```
[Strongswan examples.](https://www.strongswan.org/testresults4.html)

### Useful commands
`ping -c 3 <TO_IP>` - send just 3 packets to destination

## [5. AAA](https://ucilnica.fri.uni-lj.si/mod/page/view.php?id=9139)<a name="5"/>

### Radius server with a test client
##### Register new client (NAS) to RADIUS server
Add to file `sudo nano /etc/freeradius/3.0/clients.conf` (if not already):
```
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
    require_message_authenticator = no
    nas_type = other
}
```
##### Add new end-user to DB
Add to file `/etc/freeradius/3.0/users`:
```sh
"alice" Cleartext-Password := "password"
```
`sudo service freeradius stop` - stop service\
`sudo freeradius -X -d /etc/freeradius/3.0` - run RADIUS server in foreground with debugging\
`echo "User-Name=alice, User-Password=password" | radclient 127.0.0.1 auth testing123 -x` - send authentication request to test RADIUS server


### HTTP authentication with Apache and FreeRADIUS

Enable `auth_radius` module:
`sudo a2enmod auth_radius` - enable module\
`sudo service apache2 restart` - restart Apache\
\
Add to file `sudo nano /etc/apache2/ports.conf`:
```apache
# FreeRADIUS runs on localhost:1812 (standard RADIUS port).
# Apache will authenticate itself to the AAA server with PSK 'testing123'.
# The request shall time-out after 5 seconds, and retry at most 3 times.
AddRadiusAuth localhost:1812 testing123 5:3

# Next line configures the time (in minutes) in which the authentication cookie
# set by the Apache server expires
AddRadiusCookieValid 1
```
Add to `<VirtualHost *:80>` in file `sudo nano /etc/apache2/sites-available/000-default.conf`:
```apache
<Directory /var/www/html>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride None

    # ADD LINE 1
    # Use basic password authentication
    # AuthType Digest won't work with RADIUS
    AuthType Basic

    # ADD LINE 2
    # Tell the user the realm to which they are authenticating.
    AuthName "RADIUS Authentication for my site"

    # ADD LINE 3
    # Set RADIUS to be provider for this basic authentication
    AuthBasicProvider radius

    # ADD LINE 4
    # Require that mod_auth_radius returns a valid user,
    # otherwise access is denied.
    Require valid-user
</Directory>
```
Run:\
`sudo service apache2 reload` - reload Apache\
`sudo freeradius -X -d /etc/freeradius/3.0` - start FreeRADIUS\
`curl --user alice:password http://localhost -v` - test login to localhost

### Roaming
##### RADIUS 1
**Create domain (domain.com)**
Add to file `sudo nano /etc/freeradius/3.0/proxy.conf`:
```
home_server hs_domain_com {
        type = auth+acct
        ipaddr = $RADIUS2
        port = 1812
        secret = testing123
}

home_server_pool pool_domain_com {
        type = fail-over
        home_server = hs_domain_com
}

realm domain.com {
        pool = pool_domain_com
        nostrip
}
```

##### RADIUS 2
**Create local domain (domain.com)**
Add to file `sudo nano /etc/freeradius/3.0/proxy.conf`:
```
realm domain.com {
}
```
**Add new AAA proxy (client)**
Add to file `sudo nano /etc/freeradius/3.0/clients.conf`:
```
client $RADIUS1 {
    secret = testing123
}
```
**Add new end-user**
Add to file `/etc/freeradius/3.0/users`:
```sh
"bob" Cleartext-Password := "password"
```
`sudo service freeradius stop` - stop service\
`sudo freeradius -X -d /etc/freeradius/3.0` - run RADIUS server in foreground with debugging\
\
`curl --user bob@domain.com:password http://localhost -v` - test login to localhost **from RADIUS 1**



