#!/bin/bash

HTTP_PROXY="http://example.com/"
HTTPS_PROXY="http://example.com/"

ANSIBLE_PLAYBOOK=./ansible-Proxy/site.yml
TMP_INVENTORY="/tmp/setup_hosts"


echo "[server]" > ${TMP_INVENTORY}


cat <<EOF > ./ansible-Proxy/roles/proxy/vars/main.yml
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

    uvt-kvm ssh ${i} "sudo echo 'Acquire::http::Proxy \"${HTTP_PROXY}\";' > apt.conf" --insecure
    uvt-kvm ssh ${i} "sudo echo 'Acquire::https::Proxy \"${HTTPS_PROXY}\";' >> apt.conf" --insecure
    uvt-kvm ssh ${i} "sudo mv apt.conf /etc/apt/" --insecure
    uvt-kvm ssh ${i} "sudo apt-get install python -y" --insecure

    echo ${INSTANCE_IP} >> ${TMP_INVENTORY}

done

ansible-playbook -i ${TMP_INVENTORY} ${ANSIBLE_PLAYBOOK}
