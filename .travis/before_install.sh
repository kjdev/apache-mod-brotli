#!/bin/bash

sudo apt-get update -qq

if [ "${APACHE_VERSION}" = "2.4.x" ]; then
  sudo apt-get install -qq software-properties-common python-software-properties
  sudo apt-add-repository -y ppa:ondrej/apache2
  sudo apt-get update -qq
fi

sudo apt-get install -qq apache2 apache2-dev automake libtool autotools-dev make
