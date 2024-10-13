FROM ubuntu:22.04

WORKDIR /root

# Update and Upgrade system
RUN apt update && apt upgrade -y

# Install useful tools (ifconfig, ip route, ping, nano , wget)
RUN apt install net-tools -y
RUN apt install iproute2 -y
RUN apt install inetutils-ping -y
RUN apt install nano -y
RUN apt install wget -y

# Install Python and useful Python tools
RUN apt install python3 -y
RUN apt install python3-pip -y
RUN apt install python3.10-venv -y

# Install Kerbrute
RUN wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
RUN mv kerbrute_linux_amd64 kerbrute
RUN chmod +x kerbrute

# Install LDAP utils
RUN apt install ldap-utils -y

# Install the tool for Mitm
RUN apt install dsniff -y

# Install Hascaht and John the Ripper
RUN apt install john -y
RUN apt install hashcat -y

# Download source code for the modified Impacket version for Samba
RUN wget https://github.com/trovoes18/Samba-Lab/raw/main/impacket-samba.tar.gz
RUN tar -xvf impacket-samba.tar.gz

# Setup and Install Impacket
RUN python3 -m venv myenv

# 'source' doesn't exist in /bin/sh. So we need to invoke /bin/bash
RUN /bin/bash -c "source myenv/bin/activate && cd impacket && pip install -r requirements.txt && pip install ."
