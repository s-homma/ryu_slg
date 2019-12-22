#!/bin/bash

HTTP_PROXY="http://example.com/"
HTTPS_PROXY="http://example.com/"

ANSIBLE_PLAYBOOK=./ansible-Proxy/site.yml
TMP_INVENTORY="/tmp/setup_hosts"


echo "[hosts1]" > ${TMP_INVENTORY}


cat <<EOF > ./ansible-Proxy/vars/main.yml
proxy_env:
  http_proxy: "${HTTP_PROXY}"
  https_proxy: "${HTTPS_PROXY}"
EOF

for i in $@ ; do

    echo "####### Setup Proxy: ${i} ######"

    INSTANCE_IP=`sudo uvt-kvm ip ${i}`
    if [ $? != 0 ] ; then
	continue
    fi

    ssh-keygen -R ${INSTANCE_IP}

    echo ${INSTANCE_IP} >> ${TMP_INVENTORY}

done

ansible-playbook -i ${TMP_INVENTORY} ${ANSIBLE_PLAYBOOK}
