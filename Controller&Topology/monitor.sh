#!/bin/sh

touch pcap_db.pcap
chmod 777 pcap_db.pcap
tshark -i s1-eth1 -i s1-eth2 -i s1-eth3 -i s1-eth4 -a duration:60 -w pcap_db.pcap
wait
