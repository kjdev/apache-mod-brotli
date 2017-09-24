# mod_brotli

> NOTE: Please use the official module since Apache 2.4.26 : [Apache Module mod_brotli](https://httpd.apache.org/docs/2.4/en/mod/mod_brotli.html)

[![Build Status](https://travis-ci.org/kjdev/apache-mod-brotli.svg?branch=master)](https://travis-ci.org/kjdev/apache-mod-brotli)

mod_brotli is a Brotli compression module for Apache HTTPD Server.

## Requires

* [brotli](https://github.com/google/brotli)

## Build

```shell
git clone --depth=1 --recursive https://github.com/kjdev/apache-mod-brotli.git
cd apache-mod-brotli
./autogen.sh
./configure
make
```

## Install

```shell
install -p -m 755 -D .libs/mod_brotli.so /etc/httpd/modules/mod_brotli.so
```

## Configuration

`httpd.conf`:

```apache
# Load module
LoadModule brotli_module modules/mod_brotli.so

<IfModule brotli_module>
  # Output filter
  AddOutputFilterByType BROTLI text/html text/plain text/css text/xml

  # SetOutputFilter BROTLI
  # SetEnvIfNoCase Request_URI \.txt$ no-br

  # Compression
  ## BrotliCompressionLevel: 0-11 (default: 11)
  BrotliCompressionLevel 10

  ## BrotliWindowSize: 10-24 (default: 22)
  BrotliWindowSize 22

  # Specifies how to change the ETag header when the response is compressed
  ## BrotliAlterEtag: AddSuffix, NoChange, Remove (default: AddSuffix)
  BrotliAlterEtag AddSuffix

  # Filter note
  BrotliFilterNote Input  brotli_in
  BrotliFilterNote Output brotli_out
  BrotliFilterNote Ratio  brotli_ratio

  LogFormat '"%r" %{brotli_out}n/%{brotli_in}n (%{brotli_ratio}n)' brotli
  CustomLog logs/access_log brotli
</IfModule>
```
