/*
 * mod_brotli.c: Apache Brotli module
 *
 * LoadModule brotli_module modules/mod_brotli.so
 * <IfModule mod_brotli.cc>
 *   # SetOutputFilter BROTLI
 *   # SetEnvIfNoCase Request_URI \.txt$ no-br
 *
 *   AddOutputFilterByType BROTLI text/html
 *
 *   # BrotliAlterEtag AddSuffix
 *
 *   # BrotliFilterNote
 *   # BrotliFilterNote Input  brotli_in
 *   # BrotliFilterNote Output brotli_out
 *   # BrotliFilterNote Ratio  brotli_ratio
 *   # LogFormat '"%r" %{brotli_out}n/%{brotli_in}n (%{brotli_ratio}n)' brotli
 *   # CustomLog logs/access_log brotli
 * </IfModule>
 */

#ifndef HAVE_CONFIG_H
#  include "config.h"
#  undef PACKAGE_NAME
#  undef PACKAGE_STRING
#  undef PACKAGE_TARNAME
#  undef PACKAGE_VERSION
#endif

#include <stdbool.h>
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "mod_ssl.h"

#include "brotli/encode.h"

static const char brotliFilterName[] = "BROTLI";
module AP_MODULE_DECLARE_DATA brotli_module;

#define AP_BROTLI_ETAG_NOCHANGE 0
#define AP_BROTLI_ETAG_ADDSUFFIX 1
#define AP_BROTLI_ETAG_REMOVE 2

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(brotli);
#endif

#ifndef APLOG_TRACE1
#define APLOG_TRACE1 APLOG_DEBUG
#endif

#ifndef APLOG_R_IS_LEVEL
#define APLOG_R_IS_LEVEL(r,level) false
#endif

#ifndef APLOGNO
#define APLOGNO(n) "AH" #n ": "
#endif

typedef struct brotli_filter_config_t
{
  int compressionlevel;
  int windowSize;
  const char *note_ratio_name;
  const char *note_input_name;
  const char *note_output_name;
  int etag_opt;
} brotli_filter_config;

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *mod_brotli_ssl_var = NULL;

static void *
create_brotli_server_config(apr_pool_t *p, server_rec *s)
{
  brotli_filter_config *c = (brotli_filter_config *)apr_pcalloc(p, sizeof *c);

  c->compressionlevel = BROTLI_DEFAULT_QUALITY;
  c->windowSize = BROTLI_DEFAULT_WINDOW;
  c->etag_opt = AP_BROTLI_ETAG_ADDSUFFIX;

  return c;
}

static const char *
brotli_set_compressionlevel(cmd_parms *cmd, void *dummy, const char *arg)
{
  brotli_filter_config *c;
  c = (brotli_filter_config *)ap_get_module_config(cmd->server->module_config,
                                                   &brotli_module);
  int i = atoi(arg);

  if (i < 0) {
    return "BrotliCompression Level should be positive";
  }

  if (i < BROTLI_MIN_QUALITY || i > BROTLI_MAX_QUALITY) {
    return "BrotliCompression level is not a valid range";
  }

  c->compressionlevel = i;

  return NULL;
}

static const char *
brotli_set_window_size(cmd_parms *cmd, void *dummy, const char *arg)
{
  brotli_filter_config *c;
  c = (brotli_filter_config *)ap_get_module_config(cmd->server->module_config,
                                                   &brotli_module);
  int i = atoi(arg);

  if (i < BROTLI_MIN_WINDOW_BITS || i > BROTLI_MAX_WINDOW_BITS) {
    return "BrotliWindowSize is not a valid range";
  }

  c->windowSize = i;

  return NULL;
}

static const char *
brotli_set_etag(cmd_parms *cmd, void *dummy, const char *arg)
{
  brotli_filter_config *c;
  c = (brotli_filter_config *)ap_get_module_config(cmd->server->module_config,
                                                   &brotli_module);

  if (!strcasecmp(arg, "NoChange")) {
    c->etag_opt = AP_BROTLI_ETAG_NOCHANGE;
  } else if (!strcasecmp(arg, "AddSuffix")) {
    c->etag_opt = AP_BROTLI_ETAG_ADDSUFFIX;
  } else if (!strcasecmp(arg, "Remove")) {
    c->etag_opt = AP_BROTLI_ETAG_REMOVE;
  } else {
    return "BrotliAlterEtag accepts only 'NoChange', 'AddSuffix', and 'Remove'";
  }

  return NULL;
}

static const char *
brotli_set_note(cmd_parms *cmd, void *dummy, const char *arg1, const char *arg2)
{
  brotli_filter_config *c;
  c = (brotli_filter_config *)ap_get_module_config(cmd->server->module_config,
                                                   &brotli_module);

  if (arg2 == NULL) {
    c->note_ratio_name = arg1;
  }
  else if (!strcasecmp(arg1, "ratio")) {
    c->note_ratio_name = arg2;
  }
  else if (!strcasecmp(arg1, "input")) {
    c->note_input_name = arg2;
  }
  else if (!strcasecmp(arg1, "output")) {
    c->note_output_name = arg2;
  }
  else {
    return apr_psprintf(cmd->pool, "Unknown note type %s", arg1);
  }

  return NULL;
}

typedef struct brotli_ctx_t
{
  BrotliEncoderState *state;
  apr_bucket_brigade *bb;
  unsigned int filter_init:1;
  size_t bytes_in;
  size_t bytes_out;
} brotli_ctx;

static apr_status_t
brotli_ctx_cleanup(void *data)
{
  brotli_ctx *ctx = (brotli_ctx *)data;

  if (ctx && ctx->state) {
    BrotliEncoderDestroyInstance(ctx->state);
    ctx->state = NULL;
  }

  return APR_SUCCESS;
}

/*
 * ETag must be unique among the possible representations, so a change
 * to content-encoding requires a corresponding change to the ETag.
 * This routine appends -transform (e.g., -br) to the entity-tag
 * value inside the double-quotes if an ETag has already been set
 * and its value already contains double-quotes. PR 39727
 */
static void
brotli_check_etag(request_rec *r, const char *transform, int etag_opt)
{
  const char *etag = apr_table_get(r->headers_out, "ETag");
  apr_size_t etaglen;

  if (etag_opt == AP_BROTLI_ETAG_REMOVE) {
    apr_table_unset(r->headers_out, "ETag");
    return;
  }

  if ((etag && ((etaglen = strlen(etag)) > 2))) {
    if (etag[etaglen - 1] == '"') {
      apr_size_t transformlen = strlen(transform);
      char *newtag = (char *)apr_palloc(r->pool, etaglen + transformlen + 2);
      char *d = newtag;
      char *e = d + etaglen - 1;
      const char *s = etag;

      for (; d < e; ++d, ++s) {
        *d = *s;            /* copy etag to newtag up to last quote */
      }
      *d++ = '-';           /* append dash to newtag */
      s = transform;
      e = d + transformlen;
      for (; d < e; ++d, ++s) {
        *d = *s;            /* copy transform to newtag */
      }
      *d++ = '"';           /* append quote to newtag */
      *d   = '\0';          /* null terminate newtag */

      apr_table_setn(r->headers_out, "ETag", newtag);
    }
  }
}

static int
have_ssl_compression(request_rec *r)
{
  if (mod_brotli_ssl_var == NULL) {
    return 0;
  }
  const char *comp = mod_brotli_ssl_var(r->pool, r->server, r->connection, r,
                                        (char *)"SSL_COMPRESS_METHOD");
  if (comp == NULL || *comp == '\0' || strcmp(comp, "NULL") == 0) {
    return 0;
  }
  return 1;
}

static apr_status_t
brotli_compress(unsigned int operation,
                size_t len, const char *data,
                brotli_ctx *ctx, apr_pool_t *pool,
                struct apr_bucket_alloc_t *bucket_alloc)
{
  const uint8_t *next_in = (uint8_t *)data;
  size_t avail_in = len;

  while (avail_in >= 0) {
    uint8_t *next_out = NULL;
    size_t avail_out = 0;

    if (!BrotliEncoderCompressStream(ctx->state, operation,
                                     &avail_in, &next_in,
                                     &avail_out, &next_out, NULL)) {
      return APR_EGENERAL;
    }

    if (BrotliEncoderHasMoreOutput(ctx->state)) {
      size_t size = 0;
      char *buffer = (char *)BrotliEncoderTakeOutput(ctx->state, &size);
      ctx->bytes_out += size;

      apr_bucket *b = apr_bucket_heap_create(buffer, size, NULL, bucket_alloc);
      APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
    } else if (avail_in == 0) {
      break;
    }
  }

  return APR_SUCCESS;
}

static apr_status_t
brotli_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
  apr_bucket *e;
  request_rec *r = f->r;
  brotli_ctx *ctx = (brotli_ctx *)f->ctx;
  apr_size_t len = 0, blen;
  const char *data;
  brotli_filter_config *c;

  /* Do nothing if asked to filter nothing. */
  if (APR_BRIGADE_EMPTY(bb)) {
    return APR_SUCCESS;
  }

  c = (brotli_filter_config *)ap_get_module_config(r->server->module_config,
                                                   &brotli_module);

  if (!ctx) {
    char *token;
    const char *encoding;

    if (have_ssl_compression(r)) {
      ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                    "Compression enabled at SSL level; not compressing "
                    "at HTTP level.");
      ap_remove_output_filter(f);
      return ap_pass_brigade(f->next, bb);
    }

    /* We have checked above that bb is not empty */
    e = APR_BRIGADE_LAST(bb);
    if (APR_BUCKET_IS_EOS(e)) {
      /*
       * If we already know the size of the response, we can skip
       * compression on responses smaller than the compression overhead.
       * Otherwise the headers will be sent to the client without
       * "Content-Encoding: br".
       */
      e = APR_BRIGADE_FIRST(bb);
      while (1) {
        apr_status_t rc;
        if (APR_BUCKET_IS_EOS(e)) {
          ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                        "Not compressing very small response of %"
                        APR_SIZE_T_FMT " bytes", len);
          ap_remove_output_filter(f);
          return ap_pass_brigade(f->next, bb);
        }
        if (APR_BUCKET_IS_METADATA(e)) {
          e = APR_BUCKET_NEXT(e);
          continue;
        }

        rc = apr_bucket_read(e, &data, &blen, APR_BLOCK_READ);
        if (rc != APR_SUCCESS) {
          return rc;
        }

        len += blen;

        /* 50 is for Content-Encoding and Vary headers and ETag suffix */
        if (len > 50) {
          break;
        }

        e = APR_BUCKET_NEXT(e);
      }
    }

    f->ctx = (brotli_ctx *)apr_pcalloc(r->pool, sizeof(*ctx));
    ctx = (brotli_ctx *)f->ctx;

    /*
     * Only work on main request, not subrequests,
     * that are not a 204 response with no content
     * and are not tagged with the no-br env variable
     * and not a partial response to a Range request.
     */
    if ((r->main != NULL) || (r->status == HTTP_NO_CONTENT)
        || apr_table_get(r->subprocess_env, "no-br")
        || apr_table_get(r->headers_out, "Content-Range")) {
      if (APLOG_R_IS_LEVEL(r, APLOG_TRACE1)) {
        const char *reason =
          (r->main != NULL)                         ? "subrequest" :
          (r->status == HTTP_NO_CONTENT)            ? "no content" :
          apr_table_get(r->subprocess_env, "no-br") ? "no-br" :
          "content-range";
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "Not compressing (%s)", reason);
      }
      ap_remove_output_filter(f);
      return ap_pass_brigade(f->next, bb);
    }

    /*
     * Some browsers might have problems with content types
     * other than text/html, so set br-only-text/html
     * (with browsermatch) for them
     */
    if (r->content_type == NULL
        || strncmp(r->content_type, "text/html", 9)) {
      const char *env_value = apr_table_get(r->subprocess_env,
                                            "br-only-text/html");
      if (env_value && (strcmp(env_value,"1") == 0)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "Not compressing, (br-only-text/html)");
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
      }
    }

    /*
     * Let's see what our current Content-Encoding is.
     * If it's already encoded, don't compress again.
     * (We could, but let's not.)
     */
    encoding = apr_table_get(r->headers_out, "Content-Encoding");
    if (encoding) {
      const char *err_enc;
      err_enc = apr_table_get(r->err_headers_out, "Content-Encoding");
      if (err_enc) {
        encoding = apr_pstrcat(r->pool, encoding, ",", err_enc, NULL);
      }
    } else {
      encoding = apr_table_get(r->err_headers_out, "Content-Encoding");
    }

    if (r->content_encoding) {
      encoding = encoding ? apr_pstrcat(r->pool, encoding, ",",
                                        r->content_encoding, NULL)
                          : r->content_encoding;
    }

    if (encoding) {
      const char *tmp = encoding;

      token = ap_get_token(r->pool, &tmp, 0);
      while (token && *token) {
        /* stolen from mod_negotiation: */
        if (strcmp(token, "identity") && strcmp(token, "7bit") &&
            strcmp(token, "8bit") && strcmp(token, "binary")) {
          ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                        "Not compressing (content-encoding already "
                        " set: %s)", token);
          ap_remove_output_filter(f);
          return ap_pass_brigade(f->next, bb);
        }

        /* Otherwise, skip token */
        if (*tmp) {
          ++tmp;
        }
        token = (*tmp) ? ap_get_token(r->pool, &tmp, 0) : NULL;
      }
    }

    /*
     * Even if we don't accept this request based on it not having
     * the Accept-Encoding, we need to note that we were looking
     * for this header and downstream proxies should be aware of that.
     */
    apr_table_mergen(r->headers_out, "Vary", "Accept-Encoding");

    /*
     * force-br will just force it out regardless if the browser
     * can actually do anything with it.
     */
    if (!apr_table_get(r->subprocess_env, "force-br")) {
      /* if they don't have the line, then they can't play */
      const char *accepts = apr_table_get(r->headers_in, "Accept-Encoding");
      if (accepts == NULL) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
      }

      token = ap_get_token(r->pool, &accepts, 0);
      while (token && token[0] && strcasecmp(token, "br")) {
        /* skip parameters, XXX: ;q=foo evaluation? */
        while (*accepts == ';') {
          ++accepts;
          ap_get_token(r->pool, &accepts, 1);
        }

        /* retrieve next token */
        if (*accepts == ',') {
          ++accepts;
        }
        token = (*accepts) ? ap_get_token(r->pool, &accepts, 0) : NULL;
      }

      /* No acceptable token found. */
      if (token == NULL || token[0] == '\0') {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "Not compressing (no Accept-Encoding: br)");
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
      }
    } else {
      ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                    "Forcing compression (force-br set)");
    }

    /*
     * At this point we have decided to filter the content. Let's try to
     * to initialize zlib (except for 304 responses, where we will only
     * send out the headers).
     */

    if (r->status != HTTP_NOT_MODIFIED) {
      ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);

      if (ctx->state == NULL) {
        ctx->state = BrotliEncoderCreateInstance(0, 0, 0);
        if (ctx->state == NULL) {
          ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(0474)
                        "unable to init BrotliEncoderCreateInstance: URL %s",
                        r->uri);
          ap_remove_output_filter(f);
          return ap_pass_brigade(f->next, bb);
        }

        uint32_t quality = (uint32_t)c->compressionlevel;
        uint32_t lgwin = (uint32_t)c->windowSize;
        if (len > 0) {
          while (len < (1 << (lgwin - 1)) && lgwin > BROTLI_MIN_WINDOW_BITS) {
            lgwin--;
          }
        }

        BrotliEncoderSetParameter(ctx->state, BROTLI_PARAM_QUALITY, quality);
        BrotliEncoderSetParameter(ctx->state, BROTLI_PARAM_LGWIN, lgwin);

        ctx->bytes_in = 0;
        ctx->bytes_out = 0;

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(0485)
                      "brotli encoder: quality: %d lgwin: %d", quality, lgwin);
      }

      /*
       * Register a cleanup function to ensure
       * that we cleanup the internal brotli resources.
       */
      apr_pool_cleanup_register(r->pool, ctx, brotli_ctx_cleanup,
                                apr_pool_cleanup_null);

      /*
       * Set the filter init flag so subsequent invocations know we are
       * active.
       */
      ctx->filter_init = 1;
    }

    /* If the entire Content-Encoding is "identity", we can replace it. */
    if (!encoding || !strcasecmp(encoding, "identity")) {
      apr_table_setn(r->headers_out, "Content-Encoding", "br");
    } else {
      apr_table_mergen(r->headers_out, "Content-Encoding", "br");
    }
    /* Fix r->content_encoding if it was set before */
    if (r->content_encoding) {
      r->content_encoding = apr_table_get(r->headers_out, "Content-Encoding");
    }
    apr_table_unset(r->headers_out, "Content-Length");
    if (c->etag_opt != AP_BROTLI_ETAG_NOCHANGE) {
      brotli_check_etag(r, "br", c->etag_opt);
    }

    /* For a 304 response, only change the headers */
    if (r->status == HTTP_NOT_MODIFIED) {
      ap_remove_output_filter(f);
      return ap_pass_brigade(f->next, bb);
    }

  } else if (!ctx->filter_init) {
    /*
     * Hmm.  We've run through the filter init before as we have a ctx,
     * but we never initialized.  We probably have a dangling ref.  Bail.
     */
    return ap_pass_brigade(f->next, bb);
  }

  while (!APR_BRIGADE_EMPTY(bb)) {
    /*
     * Optimization: If we are a HEAD request and bytes_sent is not zero
     * it means that we have passed the content-length filter once and
     * have more data to sent. This means that the content-length filter
     * could not determine our content-length for the response to the
     * HEAD request anyway (the associated GET request would deliver the
     * body in chunked encoding) and we can stop compressing.
     */
    if (r->header_only && r->bytes_sent) {
      ap_remove_output_filter(f);
      return ap_pass_brigade(f->next, bb);
    }

    e = APR_BRIGADE_FIRST(bb);

    if (APR_BUCKET_IS_EOS(e)) {
      /* flush the remaining data from the brotli buffers */
      apr_status_t rv = brotli_compress(BROTLI_OPERATION_FINISH, 0, NULL,
                                        ctx, r->pool, f->c->bucket_alloc);
      if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(0554)
                      "Brotli compress error");
        return rv;
      }

      /* leave notes for logging */
      if (c->note_input_name) {
        apr_table_setn(r->notes, c->note_input_name,
                       (ctx->bytes_in > 0)
                       ? apr_off_t_toa(r->pool, ctx->bytes_in)
                       : "-");
      }

      if (c->note_output_name) {
        apr_table_setn(r->notes, c->note_output_name,
                       (ctx->bytes_in > 0)
                       ? apr_off_t_toa(r->pool, ctx->bytes_out)
                       : "-");
      }

      if (c->note_ratio_name) {
        apr_table_setn(r->notes, c->note_ratio_name,
                       (ctx->bytes_in > 0)
                       ? apr_itoa(r->pool,
                                  (int)(ctx->bytes_out * 100 / ctx->bytes_in))
                       : "-");
      }

      if (ctx->state) {
        BrotliEncoderDestroyInstance(ctx->state);
        ctx->state = NULL;
      }

      /* No need for cleanup any longer */
      apr_pool_cleanup_kill(r->pool, ctx, brotli_ctx_cleanup);

      /* Remove EOS from the old list, and insert into the new. */
      APR_BUCKET_REMOVE(e);
      APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

      /*
       * Okay, we've seen the EOS.
       * Time to pass it along down the chain.
       */
      return ap_pass_brigade(f->next, ctx->bb);
    }

    if (APR_BUCKET_IS_FLUSH(e)) {
      /* Remove flush bucket from old brigade anf insert into the new. */
      APR_BUCKET_REMOVE(e);
      APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
      apr_status_t rv= ap_pass_brigade(f->next, ctx->bb);
      if (rv != APR_SUCCESS) {
        return rv;
      }
      continue;
    }

    if (APR_BUCKET_IS_METADATA(e)) {
      /*
       * Remove meta data bucket from old brigade and insert into the
       * new.
       */
      APR_BUCKET_REMOVE(e);
      APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
      continue;
    }

    /* read */
    apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
    if (!len) {
      apr_bucket_delete(e);
      continue;
    }
    if (len > APR_INT32_MAX) {
      apr_bucket_split(e, APR_INT32_MAX);
      apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
    }

    /* write */
    if (len != 0) {
      apr_status_t rv = brotli_compress(BROTLI_OPERATION_PROCESS, len, data,
                                        ctx, r->pool, f->c->bucket_alloc);
      if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(0657)
                      "Brotli compress error");
        return APR_EGENERAL;
      }
    }

    apr_bucket_delete(e);
  }

  apr_brigade_cleanup(bb);
  return APR_SUCCESS;
}

static int
mod_brotli_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                       apr_pool_t *ptemp, server_rec *s)
{
  mod_brotli_ssl_var = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
  return OK;
}

#define PROTO_FLAGS AP_FILTER_PROTO_CHANGE|AP_FILTER_PROTO_CHANGE_LENGTH

static void
register_hooks(apr_pool_t *p)
{
  ap_register_output_filter(brotliFilterName, brotli_out_filter, NULL,
                            AP_FTYPE_CONTENT_SET);
  ap_hook_post_config(mod_brotli_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec brotli_filter_cmds[] = {
  AP_INIT_TAKE1("BrotliCompressionLevel",
                brotli_set_compressionlevel, NULL, RSRC_CONF,
                "Set the Brotli Compression Level"),
  AP_INIT_TAKE1("BrotliWindowSize",
                brotli_set_window_size, NULL, RSRC_CONF,
                "Set the Brotli window size"),
  AP_INIT_TAKE1("BrotliAlterEtag",
                brotli_set_etag, NULL, RSRC_CONF,
                "Set how mod_brotli should modify ETAG response headers: 'AddSuffix' (default), 'NoChange' (2.2.x behavior), 'Remove'"),
  /*
  AP_INIT_TAKE1("BrotliBufferSize",
                brotli_set_buffer_size, NULL, RSRC_CONF,
                "Set the Brotli Buffer Size"),
  */
  AP_INIT_TAKE12("BrotliFilterNote",
                 brotli_set_note, NULL, RSRC_CONF,
                 "Set a note to report on compression ratio"),
  {NULL}
};

module AP_MODULE_DECLARE_DATA brotli_module = {
  STANDARD20_MODULE_STUFF,
  NULL,                         /* dir config creater */
  NULL,                         /* dir merger --- default is to override */
  create_brotli_server_config,  /* server config */
  NULL,                         /* merge server config */
  brotli_filter_cmds,           /* command table */
  register_hooks                /* register hooks */
};
