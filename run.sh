#!/usr/bin/env bash
echo -n "INFO:get passphrase and certificate key with permission of "
whoami
passphrase="$(</etc/certserver/ssl.pass)"
key="$(cat /etc/certserver/rootCA.key)"

run_date=`date "+%Y.%m.%d_%H:%M:%S"`

sudo -u ubuntu bash << EOF
echo -n "INFO:server open with permission of "
whoami

cd src/main
echo -e "$passphrase\n$key\n" | waitress-serve --po=on --host=127.0.0.1 --port=5000 --url-scheme=https --call app:create_app | tee -a ../../log/"$run_date".waitress-serve.log
EOF
