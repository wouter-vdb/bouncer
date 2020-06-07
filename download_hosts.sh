#!/bin/bash

curl -O https://adaway.org/hosts.txt
mv -f hosts.txt to_block_dl/adaway.hosts

curl -O https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts
mv -f hosts to_block_dl/badd-boyz.hosts

curl -O https://gitlab.com/ZeroDot1/CoinBlockerLists/raw/master/hosts
mv -f hosts to_block_dl/coinblockerlist.hosts

curl -O https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts_without_controversies.txt
mv -f KADhosts_without_controversies.txt to_block_dl/kad.hosts

curl -O http://www.malwaredomainlist.com/hostslist/hosts.txt
mv -f hosts.txt to_block_dl/malwaredomainlist.com.hosts

curl -O http://winhelp2002.mvps.org/hosts.txt
mv -f hosts.txt to_block_dl/mvps.hosts

curl -O https://someonewhocares.org/hosts
mv -f hosts to_block_dl/someonewhocares.org.hosts

curl -O https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts
mv -f hosts to_block_dl/stevenblack.hosts

#curl -O http://pgl.yoyo.org/as/serverlist.php?hostformat=hosts;showintro=0
#mv -f serverlist.php?hostformat=hosts to_block_dl/yoyo.hosts
