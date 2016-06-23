# mod_brotli

mod_brotli is Brotli compression module for Apache HTTPD Server.

## Requires

* [brotli](https://github.com/google/brotli.git)

## Build

```
% git clone --depth=1 --recursive https://github.com/kjdev/apache-mod-brotli.git
% cd apache-mod-brotli
% ./autogen.sh
% ./configure
% make
```

## Install

```
$ install -p -m 755 -D .libs/mod_brotli.so /etc/httpd/modules/mod_brotli.so
```

## Configration

`httpd.conf`:

```
# Load module
LoadModule brotli_module modules/mod_brotli.so

# Output filter
AddOutputFilterByType BROTLI text/html

# SetOutputFilter BROTLI
# SetEnvIfNoCase Request_URI \.txt$ no-brotli

# Compression
## BrotliCompressionLevel: >=0 (default: 6)
BrotliCompressionLevel 10

## BrotliWindowSize: 10-24 (default: 19)
BrotliWindowSize 22

# Filter note
BrotliFilterNote Input  brotli_in
BrotliFilterNote Output brotli_out
BrotliFilterNote Ratio  brotli_ratio

LogFormat '"%r" %{brotli_out}n/%{brotli_in}n (%{brotli_ratio}n)' brotli
CustomLog logs/access_log brotli
```
