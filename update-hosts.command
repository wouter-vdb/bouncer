cd `dirname $0`
mkdir -p to_block_dl
./download_hosts.sh
python3 generate_hosts.py
sudo mv hosts_result /etc/hosts
echo ""
echo "# hosts file updated"
dscacheutil -flushcache; sudo killall -HUP mDNSResponder
rm -rf to_block_dl
