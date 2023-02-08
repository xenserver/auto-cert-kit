#!/bin/sh
# static ip Set static IP details for interfaces
# chkconfig: 2345 5 1
# description: Sets ethernet devices IP configuration statically using XenStore.

network_file="/etc/sysconfig/network"
get_config() {
device="$1"
key="$2"
xenstore-read "vm-data/control/${device}/${key}"
}

write_config_file() {
mfile="$1"
key="$2"
val="$3"
echo -e "$key=$val" >> "$mfile"
}

write_net_config() {
device="$1"
file="/etc/sysconfig/network-scripts/ifcfg-$device"
path="vm-data/control/$device"

#Backup and Initialise File
cp "$file" "$file.bak"
echo "" > "$file"
 
if xenstore-exists "$path/ip"; then
   write_config_file "$file" "DEVICE" $device
   write_config_file "$file" "BOOTPROTO" "static"
   write_config_file "$file" "IPADDR" $(xenstore-read "$path/ip")
     
   if xenstore-exists "$path/netmask"; then
       write_config_file "$file" "NETMASK" $(xenstore-read "$path/netmask")
       echo "change ip"
       ifconfig $device $(xenstore-read "$path/ip") netmask $(xenstore-read "$path/netmask")
   fi
     
   if xenstore-exists "$path/gateway"; then
       write_config_file "$file" "GATEWAY" $(xenstore-read "$path/gateway")
       echo "change gw"
       route add default gw $(xenstore-read "$path/ip") $device
   fi
fi
  
if xenstore-exists "$path/ipv6"; then
       #Make sure no other 'NETWORKING_IPV6' variable has been set in file
       sed -i "/NETWORKING_IPV6/d" "/etc/sysconfig/network"
       write_config_file "/etc/sysconfig/network" "NETWORKING_IPV6" "yes"
       write_config_file "$file" "IPV6INIT" "yes"
       write_config_file "$file" "DEVICE" "$device"
         
       items=$(xenstore-list "$path/ipv6")
       secaddrs=""
       for key in $items; do
       if xenstore-exists "$path/ipv6/$key"; then
           if [[ "$key" == "0" ]]; then
               val=$(xenstore-read "$path/ipv6/$key/addr")
           write_config_file "$file" "IPV6ADDR" "$val"
           elif [[ "$key" == "gateway" ]]; then
           write_config_file "$file" "IPV6_DEFAULTGW" $(xenstore-read "$path/ipv6/$key")
           else
           val=$(xenstore-read "$path/ipv6/$key/addr")
           if [[ "$secaddrs" == "" ]]; then
               secaddrs="$val"
           else
               secaddrs=`echo -e "${secaddrs}\n${val}"`
           fi
           fi        
       fi
       done
       if [[ "$secaddrs" != "" ]]; then
       write_config_file "$file" "IPV6ADDR_SECONDARIES" "$secaddrs"
       fi
   fi    
}

keys=$(xenstore-list vm-data/control)
for item in $keys
do
    expr_match=$(expr $item : 'eth[0-9]\+$')
    if [ $expr_match -gt 0 ]; then
    write_net_config "$item"
    fi
done

exit 0
