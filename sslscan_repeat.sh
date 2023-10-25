#!/bin/bash

port=$1

if [ -z $port ]
then
	echo -e "Port is required!\n$0 <port>" 
	exit;
fi	

	echo $port
while read -r ip
do
	#sslscan "$ip:$port" > "$ip-sslscan-$port" 2>&1
	#testssl "$ip:$port" > "$ip-testssl-$port" 2>&1
	gobuster dir -w "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt" -t 4 -u "https://$ip:$port" -k -b 404,403 -o "$ip-gobuster-$port" 2>/dev/null
done < "scope.txt"

echo "started ssl scans!";
