# Minimal Kickstart file
install
text
reboot
lang en_US.UTF-8
keyboard us
#network --bootproto=static --ip=76.10.157.78 --netmask=255.255.255.240 --gateway=76.10.157.65 --hostname swanbase
network --bootproto=dhcp --hostname swanbase 
rootpw swan
firewall --disable
selinux --enforcing
timezone --utc America/New_York
#firstboot --disable
bootloader --location=mbr --append="console=tty0 console=ttyS0,115200 rd_NO_PLYMOUTH"
zerombr
clearpart --all --initlabel
part / --asprimary --grow 
part swap --size 1024
services --disabled=sm-client,sendmail,network,smartd,crond,atd

#Just core packages
#ensure we never accidentally get the openswan package
%packages
@core
# for now, let's not try and mix openswan rpm and /usr/local install of openswan
# later on, we will add an option to switch between "stock" and /usr/local openswan
-openswan
-sendmail
gdb
tcpdump
racoon2
nc6
# nm causes problems and steals our interfaces desipte NM_CONTROLLED="no"
-NetworkManager
# to compile openswan
gcc
make
flex
bison
gmp-devel
nss-devel
nspr-devel
unbound-devel
fipscheck-devel
libcap-ng-devel
openldap-devel
curl-devel 
redhat-rpm-config
%end

%post 
echo "nameserver 193.110.157.123" >> /etc/resolv.conf
/sbin/restorecon /etc/resolv.conf
# TODO: if rhel/centos, we should install epel-release too
yum install -y nc6 racoon2 wget vim-enhanced bison flex gmp-devel nss-devel nss-tools  gcc make kernel-devel unbound-libs

# install special service that re-mount-bind's network config based on which test host
# we are (i.e. east, west, north, ....)
# note we cannot install the serviced file from /testing, as that's not mounted during
# install time

cat << EOD > /usr/lib/systemd/system/swan-bindmount.service
[Unit]
Description=Bind mount a new /etc/sysconfig/network based on /proc/cmdline umid= VM hostname
Before=network.target

[Service]
Type=oneshot
ExecStart=/testing/fedora-setup/swan-vm-net-bindmount.py
ExecStart=/sbin/restorecon /etc/sysconfig/network*
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOD

/sbin/restorecon /usr/lib/systemd/system/swan-bindmount.service

mkdir /testing
echo "testing /testing 9p defaults,trans=virtio 0 0" >> /etc/fstab
echo "tmp /tmp 9p defaults,,noautotrans=virtio 0 0" >> /etc/fstab

cat << EOD > /etc/modprobe.d/9p.conf
# load 9p modules in time for auto mounts
options 9pnet_virtio
EOD

systemctl enable network.service
systemctl enable swan-bindmount.service

yum update -y 
%end
