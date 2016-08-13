sudo ifconfig ens33 192.168.12.133/24
sudo ip tuntap add dev asa0 mode tun
sudo ip addr add 10.0.1.1/24 dev asa0
sudo ip link set dev asa0 up
ip addr show
