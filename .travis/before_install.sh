#!/bin/bash

if [ "${APACHE_VERSION}" = "2.4.x" ]; then
  sudo apt-get update -qq
  sudo apt-get install -qq apache2 apache2-dev
else
  sudo tee -a /etc/apt/sources.list <<EOF
deb http://archive.ubuntu.com/ubuntu precise main restricted universe
deb http://archive.ubuntu.com/ubuntu precise-updates main restricted universe
deb http://security.ubuntu.com/ubuntu precise-security main restricted universe multiverse
EOF
  sudo apt-get update -qq
  apache2_version=$(apt-cache showpkg apache2 | grep 'Reverse Provides:' -C 1 | tail -1 | awk '{print $2}')
  sudo apt-get install -qq --force-yes apache2-mpm-prefork=${apache2_version} apache2-prefork-dev=${apache2_version} apache2.2-bin=${apache2_version} apache2.2-common=${apache2_version}
fi

sudo apt-get install -qq automake libtool autotools-dev make curl
