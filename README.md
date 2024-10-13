# Active Directory Labs

## Description

This repository provides penstesters and students with two intentionally vulnerable Active Directory (AD) environments using Samba and Microsoft AD within the GNS3 network emulator, which can be used to practice and learn Active Directory pentesting.

You might wonder, why use Samba? The idea behind this project is simple: running local Microsoft AD environments can demand significant physical resources, making them unfeasible for some users, particularlly for students. While cloud-based labs can solve this issue, they come with financial costs that aren’t always viable. Additionally, cloud-based solutions have limited support for multicast protocols.

Well since Samba is a linux application that emulates AD environments therefore tends to be much more resource efficient. Thats where Samba comes in. It provides you a local and free lightweight AD environment where you can practice and learn the most common AD vulnerabilities. By running within the GNS3 network emulator, it also allows for packet visualization through Wireshark and supports any network protocol.

This repository provides manual instructions to build both Samba and Microsoft AD labs, making it a great starting point for those new to Active Directory and its security. The best part? You have the flexibility to choose which environment to work with! 


## Summary
This repository walks you through setting up two AD pentesting labs: one with Samba (domain polaris.org) and the other using Windows Active Directory (domain polaris.local). Both labs use the same network setup, users, and vulnerabilities (where applicable), but differ in their environments and domain configurations. You can follow the full lab setup in this guides ([Samba Lab](./Samba%20Lab/Samba_configurations.md), [Windows Lab](./Microsoft%20AD%20Lab/Windows_configurations.md)).

The topology includes several components such as the Domain Controller (DC), the Client Workstation (DM), and the Attacker
machines (Attacker and Attacker2), all interconnected through the Switch (SW) to simulate a realistic
network environment suitable for testing various Active Directory attacks. Additionally, a NAT is required
to provide Internet access within the GNS3 environment, enabling updates, tool installations, and other
necessary connectivity for the laboratory.

![Network Topology](Utils/network_topology.png)


The domain users are consistent in both laboratories and the Table below lists the domain users, their roles, and associated credentials.

|    **User**   |    **Password**   | **Description**                                  |
|:-------------:|:-----------------:|--------------------------------------------------|
| Administrator | Passw0rd          | Administrative Account                           |
|  skyler.white | Password123       | Weak Password                                    |
|  saul.goodman | beTTer@caLL@me    | Password in the Description                      |
| jesse.pinkman | Wang0Tang0!       | Kerberos disabled Pre-Authentication             |
|  walter.white | Metho1o590oA$elry | SPN/ Sonstrained Delegation (Windows)            |
| hank.schrader | sHyangja@10       | Regular User (Samba) \| ACLs and GPOs (Windows)  |


## Attacks tested
### Samba Lab
- User Enumeration
- Password Spraying
- LDAP Dump
- AS-REP Roasting
- Kerberoasting
- NTLM Relay


### Windows Lab
- User Enumeration
- Password Spraying
- LDAP Dump
- AS-REP Roasting
- Kerberoasting
- NTLM Relay
- Golden Ticket
- ACLs/GPOs Abuse
- Constrained Delegation

## Requirements
- GNS3 Network Emulator



