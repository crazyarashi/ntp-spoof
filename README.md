# ntp-spoof
A scapy script for spoofing NTP responses with a MITM attack

1. ARP-Cache-Poisons the target and the gateway
2. Positions your machine between target and gateway in MITM attack
3. Listens for NTP-responses from gateway to target
4. Modifies the NTP-timestamps

# ntp-spoof.py
Run the script:

    sudo ./ntp-spoof.py -i enp0s25 -t 192.168.1.42 -g 192.168.1.1 -d 13:37-31.12.1983

