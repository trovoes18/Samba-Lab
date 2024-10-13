FROM ubuntu:bionic-20180426

WORKDIR /root
COPY samba.sh .
RUN chmod +x samba.sh && ./samba.sh

# Update and Upgrade system
RUN apt update
RUN apt upgrade -y

# Install useful tools (ifconfig, ip route, ping, nano , wget)
RUN apt install net-tools -y
RUN apt install iproute2 -y
RUN apt install inetutils-ping -y
RUN apt-get install nano -y
RUN apt install wget -y

# Install MIT Kerberos
RUN wget https://github.com/trovoes18/Samba-Lab/raw/main/krb5-1.21.2.tar.gz
RUN tar -xvf krb5-1.21.2.tar.gz

RUN apt-get install build-essential -y
RUN apt-get install bison -y
RUN apt-get install byacc -y

RUN cd krb5-1.21.2/src
RUN ./configure
RUN make
RUN make install

# Install Samba
RUN cd ~
RUN wget https://download.samba.org/pub/samba/stable/samba-4.18.5.tar.gz
RUN tar xf samba-4.18.5.tar.gz
RUN cd samba-4.18.5/bootstrap/generated-dists/ubuntu1804
RUN ./bootstrap.sh
RUN cd ../../..

# Install Samba with MIT Kerberos
RUN ./configure --with-system-mitkrb5 /usr/local --with-experimental-mit-ad-dc --with-system-mitkdc=/usr/local/sbin/krb5kdc
RUN make
RUN make install


