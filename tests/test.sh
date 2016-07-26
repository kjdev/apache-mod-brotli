#!/bin/bash

DIR=$(cd $(dirname ${BASH_SOURCE:-$0}); pwd)

failed=

function check
{
  [ -f "${DIR}/out" ] && rm -f "${DIR}/out"

  basename=$(basename "$1")

  curl -sI -H "Accept-Encoding:br" "${HOST:-localhost}$1" | egrep '^(HTTP|Content-Encoding|Content-Type)' | sed 's/; .*$//g' > "${DIR}/out"

  diff -q -Z --strip-trailing-cr "${DIR}/out" "${DIR}/response/${basename%.*}.out" > /dev/null
  if [ $? -eq 0 ]; then
    echo "SUCCEED: ${basename%.*}"
  else
    echo "FAILED : ${basename%.*}"
    echo "======="
    curl -sI -H "Accept-Encoding:br" "${HOST:-localhost}$1"
    echo "======="
    failed=1
  fi
}

: "generate contents" && {
  printf '.%.0s' {1..65537} >> ${DIR}/html/br1/test01.txt
  printf '.%.0s' {1..65537} >> ${DIR}/html/br1/test02.html
  printf '.%.0s' {1..65537} >> ${DIR}/html/br2/test03.txt
  printf '.%.0s' {1..65537} >> ${DIR}/html/br2/test04.html
  printf '.%.0s' {1..65537} >> ${DIR}/html/br2/test05.htm
}

: "/br1" && {
  check "/br1/test01.txt"
  check "/br1/test02.html"
}

: "/br2" && {
  check "/br2/test03.txt"
  check "/br2/test04.html"
  check "/br2/test05.htm"
}

[ -f "${DIR}/out" ] && rm -f "${DIR}/out"

if [ -n "${failed}" ]; then
  exit 1
fi

exit 0
