#!/bin/sh

vlan_log()
{
    logger -st vlan "$@"
}

vlan_ifname()
{
    echo "$1.$2"
}

vlan_add()
{
    [ -d "/sys/class/net/$1.$2" ] && return 0

    if [ -d "/sys/class/net/$1.vc" ]
    then
        vlan_log "Adding VLAN interface $1.$2 usig vlanctl"
        vlanctl --mcast --if-create-name $1.vc $1.$2
        vlanctl --if $1.vc --rx --tags 1 --filter-vid $2 0 --pop-tag --set-rxif $1.$2 --rule-append
        vlanctl --if $1.vc --tx --tags 0 --filter-txif $1.$2 --push-tag --set-vid $2 0 --rule-append
        vlanctl --if $1.vc --set-if-mode-rg
    else
        vlan_log "Adding VLAN interface $1.$2 usig vconfig"
        vconfig add "$1" "$2"
    fi
}

vlan_del()
{
    [ ! -d "/sys/class/net/$1.$2" ] && return 0

    if [ -d "/sys/class/net/$1.vc" ]
    then
        vlan_log "Removing VLAN interface $1.$2 using vlanctl"
        vlanctl --if-delete "$1.$2"
    else
        vlan_log "Removing VLAN interface $1.$2 using vconfig"
        vconfig rem "$1.$2"
    fi
}
