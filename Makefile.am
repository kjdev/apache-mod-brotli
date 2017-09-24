
ACLOCAL_AMFLAGS = -I m4

moddir = @APACHE_MODULEDIR@
mod_LTLIBRARIES = mod_brotli.la

brotli_SOURCES = \
	brotli/c/common/dictionary.c \
	brotli/c/enc/backward_references.c \
	brotli/c/enc/backward_references_hq.c \
	brotli/c/enc/bit_cost.c \
	brotli/c/enc/block_splitter.c \
	brotli/c/enc/brotli_bit_stream.c \
	brotli/c/enc/cluster.c \
	brotli/c/enc/compress_fragment.c \
	brotli/c/enc/compress_fragment_two_pass.c \
	brotli/c/enc/dictionary_hash.c \
	brotli/c/enc/encode.c \
	brotli/c/enc/entropy_encode.c \
	brotli/c/enc/histogram.c \
	brotli/c/enc/literal_cost.c \
	brotli/c/enc/memory.c \
	brotli/c/enc/metablock.c \
	brotli/c/enc/static_dict.c \
	brotli/c/enc/utf8_util.c

mod_brotli_la_SOURCES = mod_brotli.c $(brotli_SOURCES)

mod_brotli_la_CFLAGS = @APACHE_CFLAGS@ @BROTLI_CFLAGS@
mod_brotli_la_CPPFLAGS = @APACHE_CPPFLAGS@ @BROTLI_CPPFLAGS@
mod_brotli_la_LDFLAGS = -avoid-version -module @APACHE_LDFLAGS@ @BROTLI_LDFLAGS@ -lm
mod_brotli_la_LIBS = @APACHE_LIBS@ @BROTLI_LIBS@
