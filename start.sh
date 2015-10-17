#!/bin/sh
QUEUE_PORT_IN="6000"
QUEUE_PORT_OUT="6000"
TCP_IN="INPUT -p tcp --source-port 53 -j NFQUEUE --queue-num $QUEUE_PORT_IN"
UDP_IN="INPUT -p udp --source-port 53 -j NFQUEUE --queue-num $QUEUE_PORT_IN"
TCP_OUT="OUTPUT -p tcp --destination-port 53 -j NFQUEUE --queue-num $QUEUE_PORT_OUT"
UDP_OUT="OUTPUT -p udp --destination-port 53 -j NFQUEUE --queue-num $QUEUE_PORT_OUT"

start_divert() {
    DIV_IN="iptables -I $TCP_IN ; iptables -I $UDP_IN"
    DIV_OUT="iptables -I $TCP_OUT ; iptables -I $UDP_OUT"
    echo "Diverting incoming traffic at 53 to $QUEUE_PORT_IN"
    echo "Diverting outgoing traffic at 53 to $QUEUE_PORT_OUT"
    #echo $DIV_IN
    eval $DIV_IN
    #echo $DIV_OUT
    eval $DIV_OUT
}

end_divert() {
    END_DIV_IN="iptables -D $TCP_IN ; iptables -D $UDP_IN"
    END_DIV_OUT="iptables -D $TCP_OUT ; iptables -D $UDP_OUT"
    echo "Ending divert....."
    #echo $END_DIV_IN
    eval $END_DIV_IN
    #echo $END_DIV_OUT
    eval $END_DIV_OUT
    exit
}

trap end_divert 2
start_divert
#while :; do sleep 100; done
./bin/dns_sift
end_divert

