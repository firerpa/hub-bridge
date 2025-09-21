#!/bin/bash
if [ -d /data/ztnet ]; then
echo "Network bridge already initialized"; exit 100
fi

API=9000 ; BRIDGE=11234 ; FALLBACK=1443 ;

while [[ $# -gt 0 ]]; do
        case $1 in
                --web-port)
                        API=$2
                        shift 2
                        ;;
                --bridge-port)
                        BRIDGE=$2
                        shift 2
                        ;;
                --fallback-port)
                        FALLBACK=$2
                        shift 2
                        ;;
                *)
                        shift
                        ;;
        esac
done

set -e

IPV4=$(curl -s ipv4.ip.sb 2>/dev/null)
IPV6=$(curl -s ipv6.ip.sb || true 2>/dev/null)

args=()

[ -n "$IPV4" ] && args+=(-s "$IPV4")
[ -n "$IPV6" ] && args+=(-s "$IPV6")

echo "Detected public IPV4: ${IPV4}"
echo "Detected public IPV6: ${IPV6:-none}"

cd /data

worldinit -d /data/ztnet ${args[@]} >/dev/null 2>&1
IDENTITY=$(cat /data/ztnet/identity.pub)

SECRET=$(tr -dc 'a-z' < /dev/urandom | head -c 32)
AUTHTOKEN=$(tr -dc 'a-z' < /dev/urandom | head -c 24)
echo -n $AUTHTOKEN > /data/ztnet/authtoken

python3 -c "
from api.models import NetworkEndpoint
NetworkEndpoint.create_table()
NetworkEndpoint(control_endpoint='127.0.0.1:${BRIDGE}',
                control_auth='${AUTHTOKEN}',
                s='${IPV4}/${BRIDGE}',
                s_v6='${IPV6:-}/${BRIDGE}',
                s_tf='${IPV4}/${FALLBACK}',
                pub='${IDENTITY}',
                active=1
).save()
"

python3 -c "
from OpenSSL import crypto

private = crypto.PKey()
private.generate_key(crypto.TYPE_RSA, 2048)
private_key_der = crypto.dump_privatekey(crypto.FILETYPE_ASN1, private)
public_key_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, private)

open('pri.der', 'wb').write(private_key_der)
open('pub.der', 'wb').write(public_key_der)
"

echo export API=${API} >/data/environment
echo export BRIDGE=${BRIDGE} >>/data/environment
echo export SECRET=${SECRET} >>/data/environment
echo export SKEY=$(cat pri.der | base64 -w0) >>/data/environment

echo

echo -e "Your bridge api endpoint: \033[1;32mhttp://${IPV4}:${API}\033[0m"
echo -e "Your ckey (internally public): \033[1;32m$(cat pub.der | base64 -w0)\033[0m"
echo -e "Your super secret key: \033[1;32m${SECRET}\033[0m"
echo
echo -e "\033[1;31mPlease remember and save the above information.\033[0m"
echo
echo "Please ensure that your firewall:"
echo
printf "=====================================\n"
printf "|%-13s|%-8s|\033[1;32m%-14s\033[0m|\n" "${API}" "TCP" "✓"
printf "|%-13s|%-8s|\033[1;31m%-14s\033[0m|\n" "${API}" "UDP" "✗"
printf "|%-13s|%-8s|\033[1;32m%-14s\033[0m|\n" "${BRIDGE}" "UDP" "✓"
printf "|%-13s|%-8s|\033[1;31m%-14s\033[0m|\n" "${BRIDGE}" "TCP" "✗"
printf "|%-13s|%-8s|\033[1;31m%-14s\033[0m|\n" "${FALLBACK}" "UDP" "✗"
printf "|%-13s|%-8s|\033[1;32m%-14s\033[0m|\n" "${FALLBACK}" "TCP" "✓ (optional)"
printf "=====================================\n"
echo