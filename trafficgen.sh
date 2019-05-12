#!/bin/sh

#File which contains the % of Data, Mgmt and Control frames
distrib_file="distri"

#Channel on which to generate the traffic
channel=6

#802.11a /802.11b / 802.11g
mode='a'

if [ $# -eq 3 ]; then
    src=$1
    dest=$2
    essid=$3
    echo 'Src is '$src
    echo 'Dest is '$dest
    echo 'ESSID is '$essid
else
    echo 'Using default src and dest addresses ESSID of AP'
    src="000102030405"
    dest="ffffffffffff"
    essid="Zulu"

fi


#Network interface
device="ath0"

if [ $mode == 'a' ]; then
    /sbin/iwpriv $device mode 1
fi

if [ $mode == 'b' ]; then
    /sbin/iwpriv $device mode 2
fi

if [ $mode == 'g' ]; then
    /sbin/iwpriv $device mode 3
fi

/sbin/iwconfig $device channel $channel essid $essid

    
zulu -t 18 -s $src -d $dest -f $distrib_file -i $device 
