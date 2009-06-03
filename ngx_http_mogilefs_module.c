
/*
 * Copyright (C) 2009 Valery Kholodkov
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef enum {
    NGX_MOGILEFS_MAIN,
    NGX_MOGILEFS_CREATE_OPEN,
    NGX_MOGILEFS_CREATE_CLOSE,
    NGX_MOGILEFS_FETCH,
} ngx_http_mogilefs_location_type_t;

typedef struct {
    ngx_int_t                status; 
    ngx_str_t                name;
    ngx_flag_t               delete_ok;
} ngx_http_mogilefs_error_t;

typedef struct {
    ngx_uint_t               method; 
    ngx_str_t                name;
    ngx_str_t                output_param;
    ngx_str_t                output_count_param;
} ngx_http_mogilefs_cmd_t;

typedef struct {
    ngx_uint_t                 methods;
    ngx_str_t                  key;
    ngx_array_t                *key_lengths;
    ngx_array_t                *key_values;
    ngx_int_t                  index;
    ngx_http_upstream_conf_t   upstream;
    ngx_array_t                *tracker_lengths;
    ngx_array_t                *tracker_values;
    ngx_str_t                  domain;
    ngx_str_t                  fetch_location;
    ngx_flag_t                 noverify;
    ngx_http_mogilefs_location_type_t location_type;
    ngx_str_t                  create_open_spare_location;
    ngx_str_t                  create_close_spare_location;
} ngx_http_mogilefs_loc_conf_t;

typedef struct {
    ngx_str_t                 name, value;
} ngx_http_mogilefs_aux_param_t;

typedef struct {
    ngx_http_mogilefs_cmd_t  *cmd;
    ngx_array_t               sources; 
    ssize_t                   num_paths_returned;
    ngx_array_t              *aux_params;
    ngx_str_t                 key;
} ngx_http_mogilefs_ctx_t;

typedef enum {
    START,
    CREATE_OPEN,
    FETCH,
    CREATE_CLOSE,
} ngx_http_mogilefs_put_state_t;

typedef struct {
    ngx_http_post_subrequest_t      *psr;
    ngx_http_mogilefs_put_state_t    state;
    ngx_uint_t                       status;
    ngx_http_mogilefs_ctx_t         *create_open_ctx;
    ngx_str_t                        key;
} ngx_http_mogilefs_put_ctx_t;

typedef struct {
    ssize_t                   priority;
    ngx_str_t                 path;
} ngx_http_mogilefs_src_t;

static ngx_int_t ngx_http_mogilefs_eval_key(ngx_http_request_t *r, ngx_str_t *key);
static ngx_int_t ngx_http_mogilefs_put_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mogilefs_finish_phase_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);

static ngx_int_t ngx_http_mogilefs_eval_tracker(ngx_http_request_t *r, ngx_http_mogilefs_loc_conf_t *mgcf);
static ngx_int_t ngx_http_mogilefs_set_cmd(ngx_http_request_t *r, ngx_http_mogilefs_ctx_t *ctx);

static ngx_int_t ngx_http_mogilefs_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_mogilefs_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_mogilefs_process_header(ngx_http_request_t *r);
static void ngx_http_mogilefs_abort_request(ngx_http_request_t *r);
static void ngx_http_mogilefs_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t ngx_http_mogilefs_filter_init(void *data);
static ngx_int_t ngx_http_mogilefs_filter(void *data, ssize_t bytes);

static ngx_int_t ngx_http_mogilefs_parse_param(ngx_http_request_t *r, ngx_str_t *param);

static ngx_int_t ngx_http_mogilefs_path_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_mogilefs_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_mogilefs_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_mogilefs_add_variables(ngx_conf_t *cf);

static char *
ngx_http_mogilefs_tracker_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_mogilefs_pass_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_mogilefs_init(ngx_conf_t *cf);

static ngx_http_mogilefs_error_t ngx_http_mogilefs_errors[] = {
    {NGX_HTTP_NOT_FOUND,                ngx_string("unknown_key"), 1},
    {NGX_HTTP_NOT_FOUND,                ngx_string("domain_not_found"), 0},
    {NGX_HTTP_BAD_REQUEST,              ngx_string("no_key"), 0},

    {NGX_HTTP_INTERNAL_SERVER_ERROR,    ngx_null_string, 0},
};

static ngx_http_mogilefs_cmd_t ngx_http_mogilefs_cmds[] = {
    {NGX_HTTP_GET,                      ngx_string("get_paths"),            ngx_string("path"),         ngx_string("paths") },
    {NGX_HTTP_HEAD,                     ngx_string("get_paths"),            ngx_string("path_"),        ngx_string("dev_count") },
    {NGX_HTTP_PUT,                      ngx_string("create_open"),          ngx_string("path_"),        ngx_string("dev_count") },
    {NGX_HTTP_DELETE,                   ngx_string("delete"),               ngx_null_string,            ngx_null_string },

    {0,                                 ngx_null_string,                    ngx_null_string,            ngx_null_string },
};

static ngx_conf_bitmask_t  ngx_http_mogilefs_methods_mask[] = {
    { ngx_string("get"), NGX_HTTP_GET },
    { ngx_string("put"), NGX_HTTP_PUT },
    { ngx_string("delete"), NGX_HTTP_DELETE },
    { ngx_null_string, 0 }
};

static ngx_str_t  ngx_http_mogilefs_put_method = { 3, (u_char *) "PUT " };

static ngx_command_t  ngx_http_mogilefs_commands[] = {

    { ngx_string("mogilefs_pass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1|NGX_CONF_BLOCK,
      ngx_http_mogilefs_pass_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("mogilefs_tracker"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_mogilefs_tracker_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("mogilefs_domain"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mogilefs_loc_conf_t, domain),
      NULL },

    { ngx_string("mogilefs_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mogilefs_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("mogilefs_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mogilefs_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("mogilefs_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mogilefs_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("mogilefs_noverify"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mogilefs_loc_conf_t, noverify),
      NULL },

    { ngx_string("mogilefs_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mogilefs_loc_conf_t, methods),
      &ngx_http_mogilefs_methods_mask },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_mogilefs_module_ctx = {
    ngx_http_mogilefs_add_variables,       /* preconfiguration */
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

static ngx_http_variable_t  ngx_http_mogilefs_variables[] = { /* {{{ */

    { ngx_string("mogilefs_path"), NULL, ngx_http_mogilefs_path_variable,
      (uintptr_t) offsetof(ngx_http_mogilefs_ctx_t, sources),
      NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
}; /* }}} */

static ngx_str_t  ngx_http_mogilefs_path = ngx_string("mogilefs_path");

static ngx_int_t
ngx_http_mogilefs_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_upstream_t            *u;
    ngx_http_mogilefs_ctx_t        *ctx;
    ngx_http_mogilefs_loc_conf_t   *mgcf;

    mgcf = ngx_http_get_module_loc_conf(r, ngx_http_mogilefs_module);

    if (mgcf->location_type == NGX_MOGILEFS_MAIN) {
        if(!(r->method & mgcf->methods)) {
            return NGX_HTTP_NOT_ALLOWED;
        }

        if(r->method & NGX_HTTP_PUT) {
            return NGX_DECLINED;
        }
    }

    switch(r->method) {
        case NGX_HTTP_GET:
            if (ngx_http_set_content_type(r) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /* fall through */

        case NGX_HTTP_DELETE:
            rc = ngx_http_discard_request_body(r);

            if (rc != NGX_OK) {
                return rc;
            }
            break;
        default:
            break;
    }

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

    ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);
    
    if(ctx == NULL) {
        ctx = ngx_palloc(r->pool, sizeof(ngx_http_mogilefs_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->num_paths_returned = -1;
        ctx->aux_params = NULL;

        ngx_array_init(&ctx->sources, r->pool, 1, sizeof(ngx_http_mogilefs_src_t));

        if(ngx_http_mogilefs_eval_key(r, &ctx->key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_mogilefs_module);
    }

    u->input_filter_init = ngx_http_mogilefs_filter_init;
    u->input_filter = ngx_http_mogilefs_filter;
    u->input_filter_ctx = ctx;

    if (mgcf->tracker_lengths != 0) {
        if (ngx_http_mogilefs_eval_tracker(r, mgcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if(ngx_http_mogilefs_set_cmd(r, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_upstream_init(r);

    return NGX_DONE;
}

static void
ngx_http_mogilefs_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                           rc;

    rc = ngx_http_mogilefs_put_handler(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}

static ngx_int_t
ngx_http_mogilefs_put_handler(ngx_http_request_t *r)
{
    ngx_http_mogilefs_put_ctx_t        *ctx;
    ngx_str_t                           args; 
    ngx_uint_t                          flags;
    ngx_http_request_t                 *sr; 
    ngx_str_t                           spare_location = ngx_null_string, uri;
    ngx_int_t                           rc;
    u_char                             *p;
    ngx_http_core_loc_conf_t           *clcf;
    ngx_http_mogilefs_loc_conf_t       *mgcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "mogilefs put handler");

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    mgcf = ngx_http_get_module_loc_conf(r, ngx_http_mogilefs_module);

    if (clcf->handler != ngx_http_mogilefs_handler ||
        (mgcf->location_type == NGX_MOGILEFS_MAIN && !(r->method & mgcf->methods)))
    {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);

    if(ctx == NULL) {
        ctx = ngx_palloc(r->pool, sizeof(ngx_http_mogilefs_put_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ctx->psr = NULL;
        ctx->state = START;
        ctx->status = 0;
        ctx->create_open_ctx = NULL;

        if(ngx_http_mogilefs_eval_key(r, &ctx->key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_mogilefs_module);
    }

    if(ctx->psr == NULL) {
        ctx->psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if (ctx->psr == NULL) {
            return NGX_ERROR;
        }
    }

    if(r->request_body == NULL) {
        rc = ngx_http_read_client_request_body(r, ngx_http_mogilefs_body_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;
    }

    switch(ctx->state) {
        case START:
            spare_location = mgcf->create_open_spare_location;
            ctx->state = CREATE_OPEN;
            break;
        case CREATE_OPEN:
            spare_location = mgcf->fetch_location;
            ctx->state = FETCH;
            break;
        case FETCH:
            spare_location = mgcf->create_close_spare_location;
            ctx->state = CREATE_CLOSE;
            break;
        case CREATE_CLOSE:
            if(ctx->status == NGX_OK) {
                r->headers_out.content_length_n = 0;
                r->headers_out.status = NGX_HTTP_CREATED;
            }
            else {
                r->headers_out.status = ctx->status;
            }

            r->header_only = 1;

            return ngx_http_send_header(r);
    }

    uri.len = spare_location.len + ctx->key.len;

    uri.data = ngx_palloc(r->pool, uri.len);

    p = ngx_cpymem(uri.data, spare_location.data, spare_location.len);

    p = ngx_cpymem(p, ctx->key.data, ctx->key.len);

    args.len = 0;
    args.data = NULL;
    flags = 0;

    if (ngx_http_parse_unsafe_uri(r, &uri, &args, &flags) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->psr->handler = ngx_http_mogilefs_finish_phase_handler;
    ctx->psr->data = ctx;

    flags |= NGX_HTTP_SUBREQUEST_IN_MEMORY|NGX_HTTP_SUBREQUEST_WAITED;

    rc = ngx_http_subrequest(r, &uri, &args, &sr, ctx->psr, flags);

    if (rc == NGX_ERROR) {
        return rc;
    } 

    if(ctx->state == CREATE_CLOSE) {
        ngx_http_set_ctx(sr, ctx->create_open_ctx, ngx_http_mogilefs_module);
    }

    sr->method = NGX_HTTP_PUT;
    sr->method_name = ngx_http_mogilefs_put_method;

    /*
     * Wait for subrequest to complete
     */
    return NGX_DONE;
}

static ngx_int_t
ngx_http_mogilefs_finish_phase_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_mogilefs_put_ctx_t *ctx = data;

    if(rc == NGX_OK && ctx->state == CREATE_OPEN) {
        ctx->create_open_ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);
    }

    ctx->status = rc;

    return rc;
}

static ngx_int_t
ngx_http_mogilefs_eval_tracker(ngx_http_request_t *r, ngx_http_mogilefs_loc_conf_t *mgcf)
{
    ngx_str_t             tracker;
    ngx_http_upstream_t  *u;

    if (ngx_http_script_run(r, &tracker, mgcf->tracker_lengths->elts, 0,
                            mgcf->tracker_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

    u = r->upstream;

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    u->resolved->host = tracker;
    u->resolved->no_port = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_eval_key(ngx_http_request_t *r, ngx_str_t *key)
{
    size_t                          loc_len;
    ngx_http_mogilefs_loc_conf_t   *mgcf;
    ngx_http_core_loc_conf_t       *clcf;

    mgcf = ngx_http_get_module_loc_conf(r, ngx_http_mogilefs_module);
    /*
     * If key is empty take the remaining part of request URI,
     * otherwise run script to obtain key
     */
    if(mgcf->key.len == 0) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        loc_len = r->valid_location ? clcf->name.len : 0;

        key->data = r->uri.data + loc_len;
        key->len = r->uri.len - loc_len;
    }
    else {
        if(mgcf->key_lengths != NULL) {
            if (ngx_http_script_run(r, key, mgcf->key_lengths->elts, 0,
                                    mgcf->key_values->elts)
                == NULL)
            {
                return NGX_ERROR;
            }
        }
        else {
            *key = mgcf->key;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_set_cmd(ngx_http_request_t *r, ngx_http_mogilefs_ctx_t *ctx)
{
    ngx_http_mogilefs_cmd_t *c;

    c = ngx_http_mogilefs_cmds;

    while(c->name.data != NULL) {
        if(c->method & r->method)
            break;

        c++;
    }

    if(c->name.data != NULL) {
        ctx->cmd = c;
        return NGX_OK;
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_mogilefs_create_request(ngx_http_request_t *r)
{
    size_t                          len;
    uintptr_t                       escape_domain, escape_key;
    ngx_str_t                       cmd;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_mogilefs_loc_conf_t   *mgcf;
    ngx_str_t                       request;
    ngx_http_mogilefs_ctx_t        *ctx;
    ngx_http_mogilefs_aux_param_t  *a;
    ngx_uint_t                      i;

    mgcf = ngx_http_get_module_loc_conf(r, ngx_http_mogilefs_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);

    cmd = ctx->cmd->name;

    if(mgcf->location_type == NGX_MOGILEFS_CREATE_CLOSE && ctx->cmd->method & NGX_HTTP_PUT) {
        cmd.data = (u_char*)"create_close";
        cmd.len = sizeof("create_close") - 1;
    }

    if(ctx->key.len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    escape_domain = 2 * ngx_escape_uri(NULL, mgcf->domain.data, mgcf->domain.len, NGX_ESCAPE_MEMCACHED);
    escape_key = 2 * ngx_escape_uri(NULL, ctx->key.data, ctx->key.len, NGX_ESCAPE_MEMCACHED);

    len = cmd.len + 1 + sizeof("key=") - 1 + ctx->key.len + escape_key + 1 +
        sizeof("domain=") - 1 + mgcf->domain.len + escape_domain + sizeof(CRLF) - 1 +
        (mgcf->noverify ? 1 + sizeof("noverify=1") - 1 : 0);

    if(ctx->aux_params != NULL && ctx->aux_params->nelts) {
        a = ctx->aux_params->elts;
        for (i = 0; i < ctx->aux_params->nelts; i++) {
            len += a[i].name.len + 1 + 1 + a[i].value.len;
        }
    }

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

    b->last = ngx_copy(b->last, cmd.data, cmd.len);

    *b->last++ = ' ';

    b->last = ngx_copy(b->last, "key=", sizeof("key=") - 1);

    if (escape_key == 0) {
        b->last = ngx_copy(b->last, ctx->key.data, ctx->key.len);

    } else {
        b->last = (u_char *) ngx_escape_uri(b->last, ctx->key.data, ctx->key.len,
                                            NGX_ESCAPE_MEMCACHED);
    }

    *b->last++ = '&';

    b->last = ngx_copy(b->last, "domain=", sizeof("domain=") - 1);

    if (escape_domain == 0) {
        b->last = ngx_copy(b->last, mgcf->domain.data, mgcf->domain.len);

    } else {
        b->last = (u_char *) ngx_escape_uri(b->last, mgcf->domain.data, mgcf->domain.len,
                                            NGX_ESCAPE_MEMCACHED);
    }

    if(mgcf->noverify) {
        *b->last++ = '&';

        b->last = ngx_copy(b->last, "noverify=1", sizeof("noverify=1") - 1);
    }

    if(ctx->aux_params != NULL && ctx->aux_params->nelts) {
        a = ctx->aux_params->elts;
        for (i = 0; i < ctx->aux_params->nelts; i++) {
            *b->last++ = '&';

            b->last = ngx_copy(b->last, a[i].name.data, a[i].name.len);

            *b->last++ = '=';

            b->last = ngx_copy(b->last, a[i].value.data, a[i].value.len);
        }
    }

    request.data = b->pos;
    request.len = b->last - b->pos;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "mogilefs request: \"%V\"", &request);

    *b->last++ = CR; *b->last++ = LF;

    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}

static int ngx_libc_cdecl ngx_http_mogilefs_cmp_sources(const void *one,
    const void *two)
{
    ngx_http_mogilefs_src_t *first, *second;

    first = (ngx_http_mogilefs_src_t *) one;
    second = (ngx_http_mogilefs_src_t *) two;

    return first->priority - second->priority;
}

static ngx_int_t
ngx_http_mogilefs_process_ok_response(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_str_t *line)
{
    u_char                          *p;
    ngx_str_t                        param;
    ngx_int_t                        rc;

    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;
    ngx_http_mogilefs_loc_conf_t   *mgcf;
    ngx_http_variable_value_t      *v;
    ngx_http_mogilefs_ctx_t        *ctx;
    ngx_http_mogilefs_src_t        *source;

    line->data += sizeof("OK ") - 1;
    line->len -= sizeof("OK ") - 1;

    p = line->data;

    param.data = p;
    param.len = 0;

    while (*p != LF) {
        if (*p == '&' || *p == CR) {
            if(param.len != 0) {
                rc = ngx_http_mogilefs_parse_param(r, &param);

                if(rc != NGX_OK) {
                    return rc;
                }

                p++;

                param.data = p;
                param.len = 0;
            }

            if(*p == CR) {
                break;
            }
            else {
                continue;
            }
        }

        param.len++;
        p++;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);

    /*
     * Convert ok response to delete into No content
     */
    if(ctx->cmd->method & NGX_HTTP_DELETE) {
        r->headers_out.content_length_n = 0;
        u->headers_in.status_n = NGX_HTTP_NO_CONTENT;
        u->state->status = NGX_HTTP_NO_CONTENT;

        // Return no content
        u->buffer.pos = u->buffer.pos;

        return NGX_OK;
    }

    /*
     * If no paths retuned, but response was ok, tell the client it's unavailable
     */
    if((ctx->num_paths_returned <= 0 && (!(ctx->cmd->method & NGX_HTTP_PUT))) || ctx->sources.nelts == 0)
    {
        r->headers_out.content_length_n = 0;
        u->headers_in.status_n = NGX_HTTP_SERVICE_UNAVAILABLE;
        u->state->status = NGX_HTTP_SERVICE_UNAVAILABLE;

        // Return no content
        u->buffer.pos = u->buffer.pos;

        return NGX_OK;
    }

    /*
     * Sort sources and choose top source
     */
    if(ctx->sources.nelts > 1) {
        ngx_qsort(ctx->sources.elts, ctx->sources.nelts, sizeof(ngx_http_mogilefs_src_t),
            ngx_http_mogilefs_cmp_sources);
    }

    mgcf = ngx_http_get_module_loc_conf(r, ngx_http_mogilefs_module);

    source = ctx->sources.elts;
    
    /*
     * Set $mogilefs_path variable
     */
    v = r->variables + mgcf->index;

    v->data = source->path.data;
    v->len = source->path.len;

    v->not_found = 0;
    v->no_cacheable = 0;
    v->valid = 1;

    /*
     * Redirect to fetch location
     */
    if (ctx->cmd->method & NGX_HTTP_GET && r->upstream->headers_in.x_accel_redirect == NULL) {

        umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

        h = ngx_list_push(&r->upstream->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                            ngx_hash('x', '-'), 'a'), 'c'), 'c'), 'e'), 'l'), '-'), 'r'), 'e'), 'd'), 'i'), 'r'), 'e'), 'c'), 't');

        h->key.len = sizeof("X-Accel-Redirect") - 1;
        h->key.data = (u_char *) "X-Accel-Redirect";
        h->value = mgcf->fetch_location;
        h->lowcase_key = (u_char *) "x-accel-redirect";

        hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                           h->lowcase_key, h->key.len);

        if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    r->headers_out.content_length_n = 0;
    u->headers_in.status_n = 200;
    u->state->status = 200;

    // Return no content
    u->buffer.pos = u->buffer.pos;

    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_process_error_response(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_str_t *line)
{
    ngx_http_mogilefs_error_t *e;
    ngx_http_mogilefs_ctx_t   *ctx;

    line->data += sizeof("ERR ") - 1;
    line->len -= sizeof("ERR ") - 1;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "mogilefs error: \"%V\"", line);

    e = ngx_http_mogilefs_errors;

    while(e->name.data != NULL) {
        if(line->len >= e->name.len &&
            ngx_strncmp(line->data, e->name.data, e->name.len) == 0)
        {
            break;
        }

        e++;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);

    /*
     * Convert unknown_key response to delete into No content
     */
    if(ctx->cmd->method & NGX_HTTP_DELETE && e->delete_ok) {
        r->headers_out.content_length_n = 0;
        u->headers_in.status_n = NGX_HTTP_NO_CONTENT;
        u->state->status = NGX_HTTP_NO_CONTENT;

        // Return no content
        u->buffer.pos = u->buffer.pos;

        return NGX_OK;
    }

    r->headers_out.content_length_n = 0;
    u->headers_in.status_n = e->status;
    u->state->status = e->status;

    // Return no content
    u->buffer.pos = u->buffer.pos;

    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_add_aux_param(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value)
{
    ngx_http_mogilefs_ctx_t         *ctx;
    ngx_http_mogilefs_aux_param_t   *p;
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);

    if(ctx->aux_params == NULL) {
        ctx->aux_params = ngx_array_create(r->pool, 3, sizeof(ngx_http_mogilefs_aux_param_t));

        if(ctx->aux_params == NULL) {
            return NGX_ERROR;
        }
    }

    p = ngx_array_push(ctx->aux_params);
    if (p == NULL) {
        return NGX_ERROR;
    }

    p->name = *name;
    p->value = *value;

    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_parse_param(ngx_http_request_t *r, ngx_str_t *param) {
    u_char                    *p, *src, *dst;

    ngx_str_t                  name;
    ngx_str_t                  value;

    ngx_http_mogilefs_ctx_t   *ctx;
    ngx_http_mogilefs_src_t   *source;

    p = (u_char *) ngx_strchr(param->data, '=');

    if(p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "mogilefs tracker has sent invalid param: \"%V\"", param);
        return NGX_ERROR;
    }

    name.data = param->data;
    name.len = p - param->data;

    value.data = p + 1;
    value.len = param->len - (p - param->data) - 1;

    src = dst = value.data;

    ngx_unescape_uri(&dst, &src, value.len, NGX_UNESCAPE_URI);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "mogilefs param: \"%V\"=\"%V\"", &name, &value);

    ctx = ngx_http_get_module_ctx(r, ngx_http_mogilefs_module);

    if(name.len == sizeof("path") - 1
        && ngx_strncmp(name.data, "path", sizeof("path") - 1) == 0)
    {
        source = ngx_array_push(&ctx->sources);

        if(source == NULL) {
            return NGX_ERROR;
        }

        source->priority = 0;
        source->path = value;

        if(ngx_http_mogilefs_add_aux_param(r, &name, &value) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    else if(name.len >= ctx->cmd->output_param.len
        && ngx_strncmp(name.data, ctx->cmd->output_param.data, ctx->cmd->output_param.len) == 0
        && ngx_atoi(name.data + ctx->cmd->output_param.len, name.len - ctx->cmd->output_param.len) != NGX_ERROR)
    {
        source = ngx_array_push(&ctx->sources);

        if(source == NULL) {
            return NGX_ERROR;
        }

        source->priority = ngx_atoi(name.data + ctx->cmd->output_param.len, name.len - ctx->cmd->output_param.len);
        source->path = value;
    }
    else if(name.len == ctx->cmd->output_count_param.len &&
        ngx_strncmp(name.data, ctx->cmd->output_count_param.data, ctx->cmd->output_count_param.len) == 0)
    {
        ctx->num_paths_returned = ngx_atoi(value.data, value.len);
    }
    else {
        if(ngx_http_mogilefs_add_aux_param(r, &name, &value) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_mogilefs_process_header(ngx_http_request_t *r)
{
    u_char                    *p;
    ngx_str_t                  line;
    ngx_http_upstream_t       *u;

    u = r->upstream;

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    return NGX_AGAIN;
found:

    line.len = p - u->buffer.pos;
    line.data = u->buffer.pos;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "mogilefs: \"%V\"", &line);

    if (line.len >= sizeof("ERR ") - 1 &&
        ngx_strncmp(line.data, "ERR ", sizeof("ERR ") - 1) == 0)
    {
        return ngx_http_mogilefs_process_error_response(r, u, &line);
    }

    if (line.len >= sizeof("OK ") - 1 &&
        ngx_strncmp(line.data, "OK ", sizeof("OK ") - 1) == 0)
    {
        return ngx_http_mogilefs_process_ok_response(r, u, &line);
    }

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

    conf->noverify = NGX_CONF_UNSET;
    conf->methods = 0;

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

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    ngx_conf_merge_str_value(conf->domain, prev->domain, "default");

    ngx_conf_merge_value(conf->noverify, prev->noverify, 0);

    ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
                         (NGX_CONF_BITMASK_SET|NGX_HTTP_GET));

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_mogilefs_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_mogilefs_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_mogilefs_path_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) 
{
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = 0;
    v->data = (u_char*)"";

    return NGX_OK;
}

static char *
ngx_http_mogilefs_tracker_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mogilefs_loc_conf_t    *mgcf = conf;
    ngx_str_t                       *value;
    ngx_url_t                        u;
    ngx_uint_t                       n;
    ngx_http_script_compile_t        sc;

    if (mgcf->upstream.upstream || mgcf->tracker_lengths) {
        return "is duplicate";
    }

    value = cf->args->elts;

    n = ngx_http_script_variables_count(&value[1]);

    if(n) { 
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &mgcf->tracker_lengths;
        sc.values = &mgcf->tracker_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;
    u.default_port = 6001;

    mgcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (mgcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char*
ngx_http_mogilefs_create_spare_location(ngx_conf_t *cf, ngx_http_conf_ctx_t **octx, ngx_str_t *name,
    ngx_http_mogilefs_location_type_t location_type)
{
    ngx_http_mogilefs_loc_conf_t *mgcf, *pmgcf;
    ngx_http_conf_ctx_t       *ctx, *pctx = cf->ctx;
    ngx_uint_t                 i;
    ngx_http_module_t         *module;
    void                      *mconf;
    ngx_http_core_loc_conf_t  *clcf, *pclcf, *rclcf;
    ngx_http_core_srv_conf_t  *cscf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                 return NGX_CONF_ERROR;
            }

            ctx->loc_conf[ngx_modules[i]->ctx_index] = mconf;
        }
    }

    pclcf = pctx->loc_conf[ngx_http_core_module.ctx_index];

    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];

    mgcf = ctx->loc_conf[ngx_http_mogilefs_module.ctx_index];

    mgcf->location_type = location_type;

    if(location_type != NGX_MOGILEFS_FETCH) {
        pmgcf = pctx->loc_conf[ngx_http_mogilefs_module.ctx_index];

        mgcf->methods = NGX_HTTP_PUT;

        /*
         * Copy tracker configuration
         */
        mgcf->tracker_lengths = pmgcf->tracker_lengths;
        mgcf->tracker_values = pmgcf->tracker_values;

        ngx_memcpy(&mgcf->upstream, &pmgcf->upstream, sizeof(ngx_http_upstream_conf_t));

        mgcf->index = pmgcf->index;

        clcf->handler = ngx_http_mogilefs_handler;
    }

    name->len = sizeof("/mogstored_spare_") - 1 + NGX_OFF_T_LEN + 1;

    name->data = ngx_palloc(cf->pool, name->len);

    if(name->data == NULL) {
        return NGX_CONF_ERROR;
    }

    name->len = ngx_sprintf(name->data, "/mogstored_spare_%O/", (off_t)(uintptr_t)clcf) - name->data;

    clcf->loc_conf = ctx->loc_conf;
    clcf->name = *name;
    clcf->exact_match = 0;
    clcf->noname = 0;
    clcf->internal = 1;
    clcf->noregex = 1;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    rclcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

    if (ngx_http_add_location(cf, &rclcf->locations, clcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if(octx != NULL) {
        *octx = ctx;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_mogilefs_pass_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mogilefs_loc_conf_t *pmgcf = conf;
    ngx_http_core_loc_conf_t  *pclcf;
    ngx_http_conf_ctx_t       *ctx;
    char                      *rv;
    ngx_str_t                 *value;
    ngx_conf_t                 save;
    ngx_http_script_compile_t  sc;
    ngx_uint_t                 n;
    char                      *rc;

    if (pmgcf->fetch_location.len != 0) {
        return "is duplicate";
    }

    if (pmgcf->upstream.upstream == 0 && pmgcf->tracker_lengths == NULL) {
        return "no tracker defined";
    }

    pmgcf->index = ngx_http_get_variable_index(cf, &ngx_http_mogilefs_path);

    if (pmgcf->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    rc = ngx_http_mogilefs_create_spare_location(cf, NULL, &pmgcf->create_open_spare_location,
        NGX_MOGILEFS_CREATE_OPEN);

    if(rc != NGX_CONF_OK) {
        return rc;
    }

    rc = ngx_http_mogilefs_create_spare_location(cf, &ctx, &pmgcf->fetch_location,
        NGX_MOGILEFS_FETCH);

    if(rc != NGX_CONF_OK) {
        return rc;
    }

    rc = ngx_http_mogilefs_create_spare_location(cf, NULL, &pmgcf->create_close_spare_location,
        NGX_MOGILEFS_CREATE_CLOSE);

    if(rc != NGX_CONF_OK) {
        return rc;
    }

    pmgcf->location_type = NGX_MOGILEFS_MAIN;

    pclcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    pclcf->handler = ngx_http_mogilefs_handler;

    if(cf->args->nelts > 1) { 
        value = cf->args->elts;

        pmgcf->key = value[1];

        n = ngx_http_script_variables_count(&pmgcf->key);

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &pmgcf->key;
        sc.lengths = &pmgcf->key_lengths;
        sc.values = &pmgcf->key_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_LOC_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}

static ngx_int_t
ngx_http_mogilefs_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_mogilefs_put_handler;

    return NGX_OK;
}
