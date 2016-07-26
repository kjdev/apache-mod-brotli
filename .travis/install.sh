#!/bin/bash

sudo cp .libs/mod_brotli.so /usr/lib/apache2/modules/
sudo bash -c "cat ${TRAVIS_BUILD_DIR}/tests/conf/mod.conf | sed -e 's|modules/|/usr/lib/apache2/modules/|g' > /etc/apache2/mods-available/brotli.load"
sudo a2enmod brotli
