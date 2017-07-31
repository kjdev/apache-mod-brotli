#!/bin/bash

if [ "${APACHE_VERSION}" = "2.4.x" ]; then
  default=/etc/apache2/sites-enabled/000-default.conf
  conf=${TRAVIS_BUILD_DIR}/tests/conf/test.2.4.conf
else
  default=/etc/apache2/sites-enabled/000-default
  conf=${TRAVIS_BUILD_DIR}/tests/conf/test.2.2.conf
fi
sudo cp -f ${conf} ${default}

sudo mkdir -p /var/www/html/
sudo cp -R ${TRAVIS_BUILD_DIR}/tests/html/* /var/www/html/

printf '.%.0s' {1..65537} | sudo tee -a /var/www/html/br1/test01.txt
printf '.%.0s' {1..65537} | sudo tee -a /var/www/html/br1/test02.html
printf '.%.0s' {1..65537} | sudo tee -a /var/www/html/br2/test03.txt
printf '.%.0s' {1..65537} | sudo tee -a /var/www/html/br2/test04.html
printf '.%.0s' {1..65537} | sudo tee -a /var/www/html/br2/test05.htm

sudo service apache2 restart

curl -sI localhost
