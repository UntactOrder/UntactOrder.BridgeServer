#!/usr/bin/env bash
# https://growingsaja.tistory.com/330
echo -n "INFO:get passphrase and certificate key with permission of "
whoami
passphrase="$(</etc/bridgeserver/ssl.pass)"
key="$(cat /etc/bridgeserver/bridge.key)"

start_date=`date "+%Y.%m.%d_%H:%M:%S"`

cd src/main
python3 ./init.py

sudo -u ubuntu bash << EOF
echo -n "INFO:server open with permission of "
whoami

echo -e "$passphrase\n$key\n" | nohup waitress-serve --po=on --host=127.0.0.1 --port=5000 --url-scheme=https --call app:create_app > ../../log/"$start_date".waitress-serve.log &
EOF
