#!/bin/bash

# Prevent restart services message.
echo '* libraries/restart-without-asking boolean true' | sudo debconf-set-selections

export DEBIAN_FRONTEND=noninteractive

apt install -y libelf-dev libpcap-dev clang make cmake build-essential m4 pkg-config gcc-multilib llvm

eval `ssh-agent`

ssh-keyscan github.com >> ~/.ssh/known_host
ssh-keyscan -H github.com >> ~/.ssh/known_hosts

ssh-add /root/.ssh/prod

# Check if we need to clone.
if [ ! -d "kilimanjaro" ] ; then
        git clone --recursive git@github.com:repo-owner/repo
fi

if [ ! -d "killtrocity" ] ; then
        git clone git@github.com:repo-owner/repo
fi

# Update Kilimanjaro.
cd kilimanjaro/
git pull
make json-c
make
systemctl stop kilimanjaro
make install
systemctl daemon-reload
systemctl start kilimanjaro
cd ..

# Update Killtrocity.
cd killtrocity
git pull
make install
systemctl daemon-reload
systemctl restart killtrocity
cd ..

# Setup correct config for Killtrocity.
echo '{"kf_addr": "xxx.xxx.xxx.xxx", "kf_port": 8003, "km_addr": "127.0.0.1", "km_port": 8002, "stress": false, "stress_array_size": 4096, "stress_count": 30}' > /etc/killtrocity/killtrocity.json

systemctl enable --now killtrocity
systemctl enable --now kilimanjaro

echo "Updated!"