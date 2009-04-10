
/*
 * Copyright (C) 2009 Valery Kholodkov
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_http_upstream_conf_t   upstream;
} ngx_http_mogilefs_loc_conf_t;

typedef struct {
    ngx_http_request_t        *request;
    ngx_str_t                 key;
    ngx_uint_t                done;
    ngx_array_t               parts; 
} ngx_http_mogilefs_ctx_t;

static ngx_int_t ngx_http_mogilefs_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_mogilefs_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_mogilefs_process_header(ngx_http_request_t *r);
static void ngx_http_mogilefs_abort_request(ngx_http_request_t *r);
static void ngx_http_mogilefs_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t ngx_http_mogilefs_filter_init(void *data);
static ngx_int_t ngx_http_mogilefs_filter(void *data, ssize_t bytes);

static ngx_int_t
ngx_http_mogilefs_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static void *ngx_http_mogilefs_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_mogilefs_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_mogilefs_init(ngx_conf_t *cf);

static char *
ngx_http_mogilefs_pass_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_mogilefs_commands[] = {

    { ngx_string("mogilefs_pass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_mogilefs_pass_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_mogilefs_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_mogilefs_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_mogilefs_create_loc_conf,     /* create location configuration */
    ngx_http_mogilefs_merge_loc_conf       /* merge location configuration */
};

ngx_module_t  ngx_http_mogilefs_module = {
    NGX_MODULE_V1,
    &ngx_http_mogilefs_module_ctx,         /* module context */
    ngx_http_mogilefs_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t
ngx_http_mogilefs_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_upstream_t            *u;
    ngx_http_mogilefs_ctx_t        *ctx;
    ngx_http_mogilefs_loc_conf_t   *mgcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    mgcf = ngx_http_get_module_loc_conf(r, ngx_http_mogilefs_module);

    u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
    if (u == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
    u->peer.lock = &r->connection->lock;
#endif

    u->output.tag = (ngx_buf_tag_t) &ngx_http_mogilefs_module;

    u->conf = &mgcf->upstream;

    u->create_request = ngx_http_mogilefs_create_request;
    u->reinit_request = ngx_http_mogilefs_reinit_request;
    u->process_header = ngx_http_mogilefs_process_header;
    u->abort_request = ngx_http_mogilefs_abort_request;
    u->finalize_request = ngx_http_mogilefs_finalize_request;

    r->upstream = u;

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_mogilefs_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    ngx_http_set_ctx(r, ctx, ngx_http_mogilefs_module);

    u->input_filter_init = ngx_http_mogilefs_filter_init;
    u->input_filter = ngx_http_mogilefs_filter;
    u->input_filter_ctx = ctx;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}

static ngx_int_t
ngx_http_mogilefs_create_request(ngx_http_request_t *r)
{
    size_t                          len;
    uintptr_t                       escape;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_mogilefs_ctx_t        *ctx;
    ngx_http_variable_value_t      *vv;
    ngx_http_mogilefs_loc_conf_t   *mgcf;

    mgcf = ngx_http_get_module_loc_conf(r, ngx_http_mogilefs_module);

    vv = ngx_http_get_indexed_variable(r, 1);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the \"$mogilefs_key\" variable is not set");
        return NGX_ERROR;
    }

    escape = 2 * ngx_escape_uri(NULL, vv->data, vv->len, NGX_ESCAPE_MEMCACHED);

    len = sizeof("get_paths ") - 1 + vv->len + escape + sizeof(CRLF) - 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    *b->last++ = 'g'; *b->last++ = 'e'; *b->last++ = 't';  *b->last++ = '_';
    *b->last++ = 'p'; *b->last++ = 'a'; *b->last++ = 't';  *b->last++ = 'h';
    *b->last++ = 's'; *b->last++ = ' ';

    ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);

    ctx->key.data = b->last;

    if (escape == 0) {
        b->last = ngx_copy(b->last, vv->data, vv->len);

    } else {
        b->last = (u_char *) ngx_escape_uri(b->last, vv->data, vv->len,
                                            NGX_ESCAPE_MEMCACHED);
    }

    ctx->key.len = b->last - ctx->key.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "mogilefs request: \"%V\"", &ctx->key);

    *b->last++ = CR; *b->last++ = LF;

    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_process_header(ngx_http_request_t *r)
{
    u_char                    *p, *len;
    ngx_str_t                  line;
    ngx_http_upstream_t       *u;
    ngx_http_mogilefs_ctx_t   *ctx;

    u = r->upstream;

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    return NGX_AGAIN;
found:

    *p = '\0';

    line.len = p - u->buffer.pos - 1;
    line.data = u->buffer.pos;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "mogilefs: \"%V\"", &line);

    p = u->buffer.pos;

    ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);

    if (ngx_strncmp(p, "paths ", sizeof("paths ") - 1) == 0) {

        p += sizeof("paths ") - 1;

        /* skip flags */

        while (*p) {
            if (*p++ == ' ') {
                goto length;
            }
        }

        goto no_valid;

    length:

        len = p;

        while (*p && *p++ != CR) { /* void */ }

        r->headers_out.content_length_n = 0;
        u->headers_in.status_n = 200;
        u->state->status = 200;
        u->buffer.pos = p + 1;

        return NGX_OK;
    }

no_valid:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "mogilefs tracker has sent invalid response: \"%V\"", &line);

    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
}

static void
ngx_http_mogilefs_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort mogilefs request");
    return;
}

static void
ngx_http_mogilefs_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize mogilefs request");
    return;
}

static ngx_int_t
ngx_http_mogilefs_filter_init(void *data)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_filter(void *data, ssize_t bytes)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_header_filter(ngx_http_request_t *r) {
    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_str_t               *uri, args;
    ngx_int_t                rc;
    ngx_uint_t               i, flags, last;
    ngx_http_request_t      *sr;
    ngx_http_mogilefs_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "mogilefs body filter: no ctx");
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->done) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "mogilefs body filter: done");
        return ngx_http_next_body_filter(r, in);
    }

    /*
     * Ignore body that comes to us, replace it with subrequests.
     */

    last = 0;

    while(in) {
        in->buf->pos = in->buf->last;

        if (in->buf->last_buf) {
            last = 1;
            in->buf->last_buf = 0;
        }

        in = in->next;
    }

    if (!last) {
        return NGX_OK;
    }

    ctx->done = 1;

    uri = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {

        args.len = 0;
        args.data = NULL;
        flags = 0;

        if (ngx_http_parse_unsafe_uri(r, &uri[i], &args, &flags) != NGX_OK) {
            return NGX_ERROR;
        }

        rc = ngx_http_subrequest(r, &uri[i], &args, &sr, NULL, flags);

        if (rc == NGX_ERROR || rc == NGX_DONE) {
            return rc;
        }
    }

    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

static void *
ngx_http_mogilefs_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mogilefs_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mogilefs_loc_conf_t));

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    return conf;
}

static char *
ngx_http_mogilefs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mogilefs_loc_conf_t *prev = parent;
    ngx_http_mogilefs_loc_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_mogilefs_pass_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    size_t                           add;
    u_short                          port;
    ngx_url_t                        u;
    ngx_str_t                       *value, *url;
    ngx_http_mogilefs_loc_conf_t    *mgcf = conf;
    ngx_http_core_loc_conf_t        *clcf;

    if (mgcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    url = &value[1];

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (ngx_strncasecmp(url->data, (u_char *) "mogilefs://", 11) == 0) {
        add = 11;
        port = 7501;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    mgcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (mgcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf->handler = ngx_http_mogilefs_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_mogilefs_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_mogilefs_body_filter; 

    return NGX_OK;
} 

