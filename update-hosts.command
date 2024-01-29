cd `dirname $0`
python3 generate_hosts.py
sudo cp build/hosts /etc/hosts
echo ""
echo "# hosts file updated"
dscacheutil -flushcache; sudo killall -HUP mDNSResponder
