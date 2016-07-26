#!/bin/bash

if [ "${APACHE_VERSION}" = "2.4.x" ]; then
  conf=/etc/apache2/sites-available/000-default.conf
  sudo cp -f "${TRAVIS_BUILD_DIR}/tests/conf/test.conf" ${conf}
else
  conf=/etc/apache2/sites-available/default
  sudo bash -c "cat ${TRAVIS_BUILD_DIR}/tests/conf/test.conf | sed -e 's%#\([Allow|Order]\)%\1%gi' -e 's%\(Require\)%#\1%g' > ${conf}"
fi

sudo sed -e "s|/var/www/html|${TRAVIS_BUILD_DIR}/tests/html|g" --in-place ${conf}

sudo service apache2 restart

curl -sI localhost
