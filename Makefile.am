
ACLOCAL_AMFLAGS = -I m4

moddir = @APACHE_MODULEDIR@
mod_LTLIBRARIES = mod_brotli.la

brotli_SOURCES = \
	brotli/common/dictionary.c \
	brotli/enc/backward_references.c \
	brotli/enc/backward_references_hq.c \
	brotli/enc/bit_cost.c \
	brotli/enc/block_splitter.c \
	brotli/enc/brotli_bit_stream.c \
	brotli/enc/cluster.c \
	brotli/enc/compress_fragment.c \
	brotli/enc/compress_fragment_two_pass.c \
	brotli/enc/dictionary_hash.c \
	brotli/enc/encode.c \
	brotli/enc/entropy_encode.c \
	brotli/enc/histogram.c \
	brotli/enc/literal_cost.c \
	brotli/enc/memory.c \
	brotli/enc/metablock.c \
	brotli/enc/static_dict.c \
	brotli/enc/utf8_util.c

mod_brotli_la_SOURCES = mod_brotli.c $(brotli_SOURCES)

mod_brotli_la_CFLAGS = @APACHE_CFLAGS@ @BROTLI_CFLAGS@
mod_brotli_la_CPPFLAGS = @APACHE_CPPFLAGS@ @BROTLI_CPPFLAGS@
mod_brotli_la_LDFLAGS = -avoid-version -module @APACHE_LDFLAGS@ @BROTLI_LDFLAGS@ -lm
mod_brotli_la_LIBS = @APACHE_LIBS@ @BROTLI_LIBS@
