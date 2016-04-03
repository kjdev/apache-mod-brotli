
ACLOCAL_AMFLAGS = -I m4

moddir = @APACHE_MODULEDIR@
mod_LTLIBRARIES = mod_brotli.la

brotli_SOURCES = \
	brotli/enc/backward_references.cc \
	brotli/enc/block_splitter.cc \
	brotli/enc/brotli_bit_stream.cc \
	brotli/enc/encode.cc \
	brotli/enc/encode_parallel.cc \
	brotli/enc/entropy_encode.cc \
	brotli/enc/histogram.cc \
	brotli/enc/literal_cost.cc \
	brotli/enc/metablock.cc \
	brotli/enc/static_dict.cc \
	brotli/enc/streams.cc \
	brotli/enc/utf8_util.cc \
	brotli/enc/dictionary.cc


mod_brotli_la_SOURCES = mod_brotli.cc $(brotli_SOURCES)

mod_brotli_la_CFLAGS = @APACHE_CFLAGS@ @BROTLI_CFLAGS@
mod_brotli_la_CPPFLAGS = @APACHE_CPPFLAGS@ @BROTLI_CPPFLAGS@
mod_brotli_la_LDFLAGS = -avoid-version -module @APACHE_LDFLAGS@ @BROTLI_LDFLAGS@
mod_brotli_la_LIBS = @APACHE_LIBS@ @BROTLI_LIBS@
