/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "packet.h"
#include "ssl_local.h"
#include "statem.h"
#include "statem_local.h"

/* wraps */

void __wrap_ossl_statem_fatal(SSL_CONNECTION *s, int al, int reason, const char *fmt, ...);
int __wrap_ssl_set_client_hello_version(SSL_CONNECTION *s);
int __wrap_ssl_version_supported(const SSL_CONNECTION *s, int version, const SSL_METHOD **meth);
int __wrap_SSL_SESSION_is_resumable(const SSL_SESSION *s);
int __wrap_ssl_get_new_session(SSL_CONNECTION *s, int session);
int __wrap_ssl_fill_hello_random(SSL_CONNECTION *s, int server, unsigned char *field, size_t len, DOWNGRADE dgrd);
int __wrap_RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num, unsigned int strength);
int __wrap_ssl_cipher_list_to_bytes(SSL_CONNECTION *s, STACK_OF(SSL_CIPHER) *sk, WPACKET *pkt);
int __wrap_tls_construct_extensions(SSL_CONNECTION *s, WPACKET *pkt, unsigned int context, X509 *x, size_t chainidx);
int __wrap_ssl_allow_compression(SSL_CONNECTION *s);
int __wrap_WPACKET_put_bytes__(WPACKET *pkt, uint64_t val, size_t bytes);
int __wrap_WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len);
int __wrap_WPACKET_start_sub_packet_len__(WPACKET *pkt, size_t lenbytes);
int __wrap_WPACKET_close(WPACKET *pkt);
int __wrap_WPACKET_sub_memcpy__(WPACKET *pkt, const void *src, size_t len, size_t lenbytes);

void __wrap_ossl_statem_fatal(SSL_CONNECTION *s, int al, int reason, const char *fmt, ...)
{
    function_called();
    check_expected_ptr(s);
    check_expected(al);
    check_expected(reason);
    check_expected_ptr(fmt);

    /* Side effect required by tls_construct_client_hello's error path. */
    s->statem.in_init = 1;
    s->statem.state = MSG_FLOW_ERROR;
}

int __wrap_ssl_set_client_hello_version(SSL_CONNECTION *s)
{
    function_called();
    check_expected_ptr(s);

    return mock_type(int);
}

int __wrap_ssl_version_supported(const SSL_CONNECTION *s, int version, const SSL_METHOD **meth)
{
    function_called();
    check_expected_ptr(s);
    check_expected(version);
    check_expected_ptr(meth);

    return mock_type(int);
}

int __wrap_SSL_SESSION_is_resumable(const SSL_SESSION *s)
{
    function_called();
    check_expected_ptr(s);

    return mock_type(int);
}

int __wrap_ssl_get_new_session(SSL_CONNECTION *s, int session)
{
    function_called();
    check_expected_ptr(s);
    check_expected(session);

    return mock_type(int);
}

int __wrap_ssl_fill_hello_random(SSL_CONNECTION *s, int server, unsigned char *field, size_t len, DOWNGRADE dgrd)
{
    function_called();
    check_expected_ptr(s);
    check_expected(server);
    check_expected_ptr(field);
    check_expected(len);
    check_expected(dgrd);

    if (field != NULL)
        memset(field, 0xAB, len);

    return mock_type(int);
}

int __wrap_RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num, unsigned int strength)
{
    function_called();
    check_expected_ptr(ctx);
    check_expected_ptr(buf);
    check_expected(num);
    check_expected(strength);

    if (buf != NULL)
        memset(buf, 0xCD, num);

    return mock_type(int);
}

int __wrap_ssl_cipher_list_to_bytes(SSL_CONNECTION *s, STACK_OF(SSL_CIPHER) *sk, WPACKET *pkt)
{
    function_called();
    check_expected_ptr(s);
    check_expected_ptr(sk);
    check_expected_ptr(pkt);

    return mock_type(int);
}

int __wrap_tls_construct_extensions(SSL_CONNECTION *s, WPACKET *pkt, unsigned int context, X509 *x, size_t chainidx)
{
    function_called();
    check_expected_ptr(s);
    check_expected_ptr(pkt);
    check_expected(context);
    check_expected_ptr(x);
    check_expected(chainidx);

    return mock_type(int);
}

int __wrap_ssl_allow_compression(SSL_CONNECTION *s)
{
    function_called();
    check_expected_ptr(s);

    return mock_type(int);
}

int __wrap_WPACKET_put_bytes__(WPACKET *pkt, uint64_t val, size_t bytes)
{
    function_called();
    check_expected_ptr(pkt);
    check_expected(val);
    check_expected(bytes);

    return mock_type(int);
}

int __wrap_WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len)
{
    function_called();
    check_expected_ptr(pkt);
    check_expected_ptr(src);
    check_expected(len);

    return mock_type(int);
}

int __wrap_WPACKET_start_sub_packet_len__(WPACKET *pkt, size_t lenbytes)
{
    function_called();
    check_expected_ptr(pkt);
    check_expected(lenbytes);

    return mock_type(int);
}

int __wrap_WPACKET_close(WPACKET *pkt)
{
    function_called();
    check_expected_ptr(pkt);

    return mock_type(int);
}

int __wrap_WPACKET_sub_memcpy__(WPACKET *pkt, const void *src, size_t len, size_t lenbytes)
{
    function_called();
    check_expected_ptr(pkt);
    check_expected_ptr(src);
    check_expected(len);
    check_expected(lenbytes);

    return mock_type(int);
}

/* expectations */

static void expect_ossl_statem_fatal(SSL_CONNECTION *s)
{
    expect_function_call(__wrap_ossl_statem_fatal);
    expect_value(__wrap_ossl_statem_fatal, s, s);
    expect_any(__wrap_ossl_statem_fatal, al);
    expect_any(__wrap_ossl_statem_fatal, reason);
    expect_any(__wrap_ossl_statem_fatal, fmt);
}

static void expect_ssl_set_client_hello_version(SSL_CONNECTION *s, int rc)
{
    expect_function_call(__wrap_ssl_set_client_hello_version);
    expect_value(__wrap_ssl_set_client_hello_version, s, s);
    will_return(__wrap_ssl_set_client_hello_version, rc);
}

static void expect_ssl_version_supported(const SSL_CONNECTION *s, int version, const SSL_METHOD **meth, int rc)
{
    expect_function_call(__wrap_ssl_version_supported);
    expect_value(__wrap_ssl_version_supported, s, s);
    expect_value(__wrap_ssl_version_supported, version, version);
    expect_value(__wrap_ssl_version_supported, meth, meth);
    will_return(__wrap_ssl_version_supported, rc);
}

static void expect_SSL_SESSION_is_resumable(const SSL_SESSION *s, int rc)
{
    expect_function_call(__wrap_SSL_SESSION_is_resumable);
    expect_value(__wrap_SSL_SESSION_is_resumable, s, s);
    will_return(__wrap_SSL_SESSION_is_resumable, rc);
}

static void expect_ssl_get_new_session(SSL_CONNECTION *s, int session, int rc)
{
    expect_function_call(__wrap_ssl_get_new_session);
    expect_value(__wrap_ssl_get_new_session, s, s);
    expect_value(__wrap_ssl_get_new_session, session, session);
    will_return(__wrap_ssl_get_new_session, rc);
}

static void expect_ssl_fill_hello_random(SSL_CONNECTION *s, int server, unsigned char *field, size_t len, DOWNGRADE dgrd, int rc)
{
    expect_function_call(__wrap_ssl_fill_hello_random);
    expect_value(__wrap_ssl_fill_hello_random, s, s);
    expect_value(__wrap_ssl_fill_hello_random, server, server);
    expect_value(__wrap_ssl_fill_hello_random, field, field);
    expect_value(__wrap_ssl_fill_hello_random, len, len);
    expect_value(__wrap_ssl_fill_hello_random, dgrd, dgrd);
    will_return(__wrap_ssl_fill_hello_random, rc);
}

static void expect_RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num, unsigned int strength, int rc)
{
    expect_function_call(__wrap_RAND_bytes_ex);
    expect_value(__wrap_RAND_bytes_ex, ctx, ctx);
    expect_value(__wrap_RAND_bytes_ex, buf, buf);
    expect_value(__wrap_RAND_bytes_ex, num, num);
    expect_value(__wrap_RAND_bytes_ex, strength, strength);
    will_return(__wrap_RAND_bytes_ex, rc);
}

static void expect_tls_construct_extensions(SSL_CONNECTION *s, WPACKET *pkt, unsigned int context, X509 *x, size_t chainidx, int rc)
{
    expect_function_call(__wrap_tls_construct_extensions);
    expect_value(__wrap_tls_construct_extensions, s, s);
    expect_value(__wrap_tls_construct_extensions, pkt, pkt);
    expect_value(__wrap_tls_construct_extensions, context, context);
    expect_value(__wrap_tls_construct_extensions, x, x);
    expect_value(__wrap_tls_construct_extensions, chainidx, chainidx);
    will_return(__wrap_tls_construct_extensions, rc);
}

static void expect_ssl_allow_compression(SSL_CONNECTION *s, int rc)
{
    expect_function_call(__wrap_ssl_allow_compression);
    expect_value(__wrap_ssl_allow_compression, s, s);
    will_return(__wrap_ssl_allow_compression, rc);
}

static void expect_WPACKET_put_bytes__(WPACKET *pkt, uint64_t val, size_t bytes, int rc)
{
    expect_function_call(__wrap_WPACKET_put_bytes__);
    expect_value(__wrap_WPACKET_put_bytes__, pkt, pkt);
    expect_value(__wrap_WPACKET_put_bytes__, val, val);
    expect_value(__wrap_WPACKET_put_bytes__, bytes, bytes);
    will_return(__wrap_WPACKET_put_bytes__, rc);
}

static void expect_WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len, int rc)
{
    expect_function_call(__wrap_WPACKET_memcpy);
    expect_value(__wrap_WPACKET_memcpy, pkt, pkt);
    expect_value(__wrap_WPACKET_memcpy, src, src);
    expect_value(__wrap_WPACKET_memcpy, len, len);
    will_return(__wrap_WPACKET_memcpy, rc);
}

static void expect_WPACKET_start_sub_packet_len__(WPACKET *pkt, size_t lenbytes, int rc)
{
    expect_function_call(__wrap_WPACKET_start_sub_packet_len__);
    expect_value(__wrap_WPACKET_start_sub_packet_len__, pkt, pkt);
    expect_value(__wrap_WPACKET_start_sub_packet_len__, lenbytes, lenbytes);
    will_return(__wrap_WPACKET_start_sub_packet_len__, rc);
}

static void expect_WPACKET_close(WPACKET *pkt, int rc)
{
    expect_function_call(__wrap_WPACKET_close);
    expect_value(__wrap_WPACKET_close, pkt, pkt);
    will_return(__wrap_WPACKET_close, rc);
}

static void expect_WPACKET_sub_memcpy__(WPACKET *pkt, const void *src, size_t len, size_t lenbytes, int rc)
{
    expect_function_call(__wrap_WPACKET_sub_memcpy__);
    expect_value(__wrap_WPACKET_sub_memcpy__, pkt, pkt);
    expect_value(__wrap_WPACKET_sub_memcpy__, src, src);
    expect_value(__wrap_WPACKET_sub_memcpy__, len, len);
    expect_value(__wrap_WPACKET_sub_memcpy__, lenbytes, lenbytes);
    will_return(__wrap_WPACKET_sub_memcpy__, rc);
}

/* ^^^ ALL OF THE ABOVE MOSTLY GENERATED BY util/mkwraps.pl ^^^ */

/* phase */
static const char *current_phase = "init";
#define PHASE(name) current_phase = (name)

/* scenario */

struct ch_scenario {
    /* protocol state */
    int version;
    int session_ssl_version;
    int client_version;
    size_t session_id_length;
    unsigned char session_id_byte;
    int hrr;
    /* deviation bits */
    unsigned new_session : 1;
    unsigned middlebox_compat : 1;
    unsigned client_random_prefilled : 1;
    unsigned tmp_session_id_preset : 1;
    unsigned version_unsupported : 1;
    unsigned not_resumable : 1;
    unsigned allow_compression : 1;
    unsigned no_comp : 1;
    /* fault injection bits */
    unsigned set_version_fail : 1;
    unsigned new_session_fail : 1;
    unsigned fill_random_fail : 1;
    unsigned rand_bytes_fail : 1;
    unsigned cipher_list_fail : 1;
    unsigned extensions_fail : 1;
    unsigned dtls_cookie_too_long : 1;
    unsigned wpkt_client_version_fail : 1;
    unsigned wpkt_random_memcpy_fail : 1;
    unsigned wpkt_session_id_open_fail : 1;
    unsigned wpkt_session_id_memcpy_fail : 1;
    unsigned wpkt_session_id_close_fail : 1;
    unsigned wpkt_dtls_cookie_fail : 1;
    unsigned wpkt_ciphers_open_fail : 1;
    unsigned wpkt_ciphers_close_fail : 1;
    unsigned wpkt_compression_open_fail : 1;
    unsigned wpkt_compression_null_fail : 1;
    unsigned wpkt_compression_close_fail : 1;
    /* expected outcome */
    int expected_rc;
};

/* fake methods */

static SSL3_ENC_METHOD fake_enc = { .enc_flags = 0 };
static SSL3_ENC_METHOD fake_enc_dtls = { .enc_flags = SSL_ENC_FLAG_DTLS };

static SSL_METHOD fake_method_tls = {
    .version = TLS1_2_VERSION,
    .ssl3_enc = &fake_enc,
};
static SSL_METHOD fake_method_dtls = {
    .version = DTLS1_2_VERSION,
    .ssl3_enc = &fake_enc_dtls,
};

/* per-test context */

struct ch_ctx {
    SSL_CONNECTION s;
    SSL_CTX ctx;
    SSL_CIPHER cipher;
    SSL_SESSION session;
    DTLS1_STATE d1;
    WPACKET pkt;
    BUF_MEM *buf;
};

/* setup */

static int ch_setup(void **state)
{
    struct ch_ctx *c = OPENSSL_zalloc(sizeof(*c));

    assert_non_null(c);
    current_phase = "init";

    c->s.ssl.ctx = &c->ctx;
    c->s.server = 0;
    c->s.session = &c->session;
    c->s.s3.tmp.new_cipher = &c->cipher;
    c->cipher.algorithm_auth = SSL_aRSA;
    c->cipher.algorithm_mkey = SSL_kRSA;

    c->buf = BUF_MEM_new();
    assert_non_null(c->buf);
    assert_true(WPACKET_init(&c->pkt, c->buf));

    *state = c;
    return 0;
}

static int ch_teardown(void **state)
{
    struct ch_ctx *c = *state;

    if (c != NULL) {
        WPACKET_cleanup(&c->pkt);
        BUF_MEM_free(c->buf);
        OPENSSL_free(c);
    }
    return 0;
}

static void setup_state(const struct ch_scenario *sc, struct ch_ctx *c)
{
    int version = sc->version ? sc->version : TLS1_2_VERSION;
    int is_dtls = (version == DTLS1_2_VERSION);
    int session_version = sc->session_ssl_version
        ? sc->session_ssl_version
        : version;

    c->s.ssl.method = is_dtls ? &fake_method_dtls : &fake_method_tls;
    c->s.version = version;
    c->s.client_version = sc->client_version ? sc->client_version : version;

    if (is_dtls)
        c->s.d1 = &c->d1;

    c->session.ssl_version = session_version;
    c->session.session_id_length = sc->session_id_length;
    if (sc->session_id_length > 0)
        memset(c->session.session_id, sc->session_id_byte,
            sc->session_id_length);

    c->s.new_session = sc->new_session;
    c->s.hello_retry_request = sc->hrr;
    c->s.options = sc->middlebox_compat ? SSL_OP_ENABLE_MIDDLEBOX_COMPAT : 0;

    if (sc->client_random_prefilled)
        c->s.s3.client_random[0] = 0x01;

    if (sc->tmp_session_id_preset) {
        memset(c->s.tmp_session_id, 0x99, sizeof(c->s.tmp_session_id));
        c->s.tmp_session_id_len = sizeof(c->s.tmp_session_id);
    }

    if (sc->dtls_cookie_too_long && is_dtls)
        c->d1.cookie_len = sizeof(c->d1.cookie) + 1;
}

/* expect ClientHello by the ch_scenario */
static void expect_ch(const struct ch_scenario *sc, struct ch_ctx *c)
{
    int version = sc->version ? sc->version : TLS1_2_VERSION;
    int is_dtls = (version == DTLS1_2_VERSION);
    int session_version = sc->session_ssl_version
        ? sc->session_ssl_version
        : version;
    int need_new_session;
    int do_fill;
    int tls13_compat;
    size_t sess_id_len;
    unsigned char *sess_id_src = NULL;

    PHASE("set_version");
    expect_ssl_set_client_hello_version(&c->s,
        sc->set_version_fail ? SSL_R_UNSUPPORTED_PROTOCOL : 0);
    if (sc->set_version_fail) {
        expect_ossl_statem_fatal(&c->s);
        return;
    }

#ifndef OPENSSL_NO_ECH
    expect_ssl_set_client_hello_version(&c->s, 0);
#endif

    PHASE("session_check");
    expect_ssl_version_supported(&c->s, session_version, NULL,
        sc->version_unsupported ? 0 : 1);
    need_new_session = sc->version_unsupported;
    if (!sc->version_unsupported) {
        expect_SSL_SESSION_is_resumable(&c->session,
            sc->not_resumable ? 0 : 1);
        need_new_session = sc->not_resumable;
    }
    if (need_new_session && sc->hrr == SSL_HRR_NONE) {
        expect_ssl_get_new_session(&c->s, 0,
            sc->new_session_fail ? 0 : 1);
        if (sc->new_session_fail)
            return;
    }

    PHASE("fill_random");
    if (is_dtls)
        do_fill = !sc->client_random_prefilled;
    else
        do_fill = (sc->hrr == SSL_HRR_NONE);
    if (do_fill) {
        expect_ssl_fill_hello_random(&c->s, 0, c->s.s3.client_random,
            SSL3_RANDOM_SIZE, DOWNGRADE_NONE,
            sc->fill_random_fail ? 0 : 1);
        if (sc->fill_random_fail) {
            expect_ossl_statem_fatal(&c->s);
            return;
        }
    }

    PHASE("client_version");
    expect_WPACKET_put_bytes__(&c->pkt, c->s.client_version, 2,
        sc->wpkt_client_version_fail ? 0 : 1);
    if (sc->wpkt_client_version_fail) {
        expect_ossl_statem_fatal(&c->s);
        return;
    }
    expect_WPACKET_memcpy(&c->pkt, c->s.s3.client_random, SSL3_RANDOM_SIZE,
        sc->wpkt_random_memcpy_fail ? 0 : 1);
    if (sc->wpkt_random_memcpy_fail) {
        expect_ossl_statem_fatal(&c->s);
        return;
    }

    PHASE("session_id_compute");
    tls13_compat = (version == TLS1_3_VERSION && sc->middlebox_compat);
    if (sc->new_session || session_version == TLS1_3_VERSION) {
        if (tls13_compat) {
            if (sc->hrr == SSL_HRR_NONE) {
                expect_RAND_bytes_ex(c->ctx.libctx, c->s.tmp_session_id,
                    sizeof(c->s.tmp_session_id), 0,
                    sc->rand_bytes_fail ? 0 : 1);
                if (sc->rand_bytes_fail) {
                    expect_ossl_statem_fatal(&c->s);
                    return;
                }
            }
            sess_id_len = sizeof(c->s.tmp_session_id);
            sess_id_src = c->s.tmp_session_id;
        } else {
            sess_id_len = 0;
        }
    } else {
        sess_id_len = sc->session_id_length;
        if (sess_id_len > 0)
            sess_id_src = c->session.session_id;
    }

    PHASE("session_id_encode");
    expect_WPACKET_start_sub_packet_len__(&c->pkt, 1,
        sc->wpkt_session_id_open_fail ? 0 : 1);
    if (sc->wpkt_session_id_open_fail) {
        expect_ossl_statem_fatal(&c->s);
        return;
    }
    if (sess_id_len > 0) {
        expect_WPACKET_memcpy(&c->pkt, sess_id_src, sess_id_len,
            sc->wpkt_session_id_memcpy_fail ? 0 : 1);
        if (sc->wpkt_session_id_memcpy_fail) {
            expect_ossl_statem_fatal(&c->s);
            return;
        }
    }
    expect_WPACKET_close(&c->pkt,
        sc->wpkt_session_id_close_fail ? 0 : 1);
    if (sc->wpkt_session_id_close_fail) {
        expect_ossl_statem_fatal(&c->s);
        return;
    }

    if (is_dtls) {
        PHASE("dtls_cookie");
        if (sc->dtls_cookie_too_long) {
            expect_ossl_statem_fatal(&c->s);
            return;
        }
        expect_WPACKET_sub_memcpy__(&c->pkt, c->d1.cookie, c->d1.cookie_len, 1,
            sc->wpkt_dtls_cookie_fail ? 0 : 1);
        if (sc->wpkt_dtls_cookie_fail) {
            expect_ossl_statem_fatal(&c->s);
            return;
        }
    }

    PHASE("ciphers_open");
    expect_WPACKET_start_sub_packet_len__(&c->pkt, 2,
        sc->wpkt_ciphers_open_fail ? 0 : 1);
    if (sc->wpkt_ciphers_open_fail) {
        expect_ossl_statem_fatal(&c->s);
        return;
    }
    PHASE("cipher_list");
    expect_function_call(__wrap_ssl_cipher_list_to_bytes);
    expect_value(__wrap_ssl_cipher_list_to_bytes, s, &c->s);
    expect_any(__wrap_ssl_cipher_list_to_bytes, sk);
    expect_value(__wrap_ssl_cipher_list_to_bytes, pkt, &c->pkt);
    will_return(__wrap_ssl_cipher_list_to_bytes,
        sc->cipher_list_fail ? 0 : 1);
    if (sc->cipher_list_fail)
        return;
    PHASE("ciphers_close");
    expect_WPACKET_close(&c->pkt,
        sc->wpkt_ciphers_close_fail ? 0 : 1);
    if (sc->wpkt_ciphers_close_fail) {
        expect_ossl_statem_fatal(&c->s);
        return;
    }

    PHASE("compression_open");
    expect_WPACKET_start_sub_packet_len__(&c->pkt, 1,
        sc->wpkt_compression_open_fail ? 0 : 1);
    if (sc->wpkt_compression_open_fail) {
        expect_ossl_statem_fatal(&c->s);
        return;
    }
#ifndef OPENSSL_NO_COMP
    if (!sc->no_comp) {
        PHASE("allow_compression");
        expect_ssl_allow_compression(&c->s, sc->allow_compression);
    }
#endif
    PHASE("compression_null");
    expect_WPACKET_put_bytes__(&c->pkt, 0, 1,
        sc->wpkt_compression_null_fail ? 0 : 1);
    if (sc->wpkt_compression_null_fail) {
        expect_ossl_statem_fatal(&c->s);
        return;
    }
    PHASE("compression_close");
    expect_WPACKET_close(&c->pkt,
        sc->wpkt_compression_close_fail ? 0 : 1);
    if (sc->wpkt_compression_close_fail) {
        expect_ossl_statem_fatal(&c->s);
        return;
    }

    PHASE("extensions");
    expect_tls_construct_extensions(&c->s, &c->pkt, SSL_EXT_CLIENT_HELLO,
        NULL, 0,
        sc->extensions_fail ? 0 : 1);
    if (sc->extensions_fail)
        return;

    PHASE("done");
}

static void run_scenario(const struct ch_scenario *sc, void **state)
{
    struct ch_ctx *c = *state;
    int rc;

    setup_state(sc, c);
    expect_ch(sc, c);
    rc = tls_construct_client_hello(&c->s, &c->pkt);
    if (rc != sc->expected_rc)
        fail_msg("rc=%d expected=%d (last phase: %s)",
            rc, sc->expected_rc, current_phase);
}

/* tests */

/* happy paths */

static void test_ch_tls12_basic(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

static void test_ch_tls12_resumable_with_session_id(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .session_id_length = 32,
        .session_id_byte = 0x11,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

static void test_ch_tls12_non_resumable_needs_new_session(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .not_resumable = 1,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

static void test_ch_tls12_unsupported_session_version(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .version_unsupported = 1,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

static void test_ch_tls13_basic(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_3_VERSION,
        .client_version = TLS1_2_VERSION,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

static void test_ch_tls13_new_session_compat(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_3_VERSION,
        .client_version = TLS1_2_VERSION,
        .new_session = 1,
        .middlebox_compat = 1,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

static void test_ch_tls13_new_session_no_compat(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_3_VERSION,
        .client_version = TLS1_2_VERSION,
        .new_session = 1,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

static void test_ch_tls13_compat_hrr_reuses_session_id(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_3_VERSION,
        .client_version = TLS1_2_VERSION,
        .new_session = 1,
        .middlebox_compat = 1,
        .hrr = SSL_HRR_PENDING,
        .tmp_session_id_preset = 1,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

static void test_ch_tls13_hrr_suppresses_new_session(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_3_VERSION,
        .client_version = TLS1_2_VERSION,
        .version_unsupported = 1,
        .hrr = SSL_HRR_PENDING,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

static void test_ch_dtls_basic(void **state)
{
    struct ch_scenario sc = {
        .version = DTLS1_2_VERSION,
        .session_ssl_version = DTLS1_2_VERSION,
        .client_random_prefilled = 1,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

static void test_ch_compression_allowed(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .allow_compression = 1,
        .expected_rc = CON_FUNC_SUCCESS,
    };
    run_scenario(&sc, state);
}

/* error paths */

static void test_ch_set_version_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .set_version_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_new_session_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .version_unsupported = 1,
        .new_session_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_fill_random_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .fill_random_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_rand_bytes_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_3_VERSION,
        .client_version = TLS1_2_VERSION,
        .new_session = 1,
        .middlebox_compat = 1,
        .rand_bytes_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_cipher_list_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .cipher_list_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_extensions_fail(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .extensions_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_dtls_cookie_too_long(void **state)
{
    struct ch_scenario sc = {
        .version = DTLS1_2_VERSION,
        .session_ssl_version = DTLS1_2_VERSION,
        .client_random_prefilled = 1,
        .dtls_cookie_too_long = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_client_version_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .wpkt_client_version_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_random_memcpy_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .wpkt_random_memcpy_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_session_id_open_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .wpkt_session_id_open_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_session_id_memcpy_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .session_id_length = 16,
        .session_id_byte = 0x11,
        .wpkt_session_id_memcpy_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_session_id_close_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .wpkt_session_id_close_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_dtls_cookie_fails(void **state)
{
    struct ch_scenario sc = {
        .version = DTLS1_2_VERSION,
        .session_ssl_version = DTLS1_2_VERSION,
        .client_random_prefilled = 1,
        .wpkt_dtls_cookie_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_ciphers_open_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .wpkt_ciphers_open_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_ciphers_close_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .wpkt_ciphers_close_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_compression_open_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .wpkt_compression_open_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_compression_null_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .wpkt_compression_null_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

static void test_ch_wpkt_compression_close_fails(void **state)
{
    struct ch_scenario sc = {
        .version = TLS1_2_VERSION,
        .wpkt_compression_close_fail = 1,
        .expected_rc = CON_FUNC_ERROR,
    };
    run_scenario(&sc, state);
}

/* main */

#define CH_UNIT_TEST(name) \
    cmocka_unit_test_setup_teardown(name, ch_setup, ch_teardown)

int main(void)
{
    const struct CMUnitTest tests[] = {
        CH_UNIT_TEST(test_ch_tls12_basic),
        CH_UNIT_TEST(test_ch_tls12_resumable_with_session_id),
        CH_UNIT_TEST(test_ch_tls12_non_resumable_needs_new_session),
        CH_UNIT_TEST(test_ch_tls12_unsupported_session_version),
        CH_UNIT_TEST(test_ch_tls13_basic),
        CH_UNIT_TEST(test_ch_tls13_new_session_compat),
        CH_UNIT_TEST(test_ch_tls13_new_session_no_compat),
        CH_UNIT_TEST(test_ch_tls13_compat_hrr_reuses_session_id),
        CH_UNIT_TEST(test_ch_tls13_hrr_suppresses_new_session),
        CH_UNIT_TEST(test_ch_dtls_basic),
        CH_UNIT_TEST(test_ch_compression_allowed),
        CH_UNIT_TEST(test_ch_set_version_fails),
        CH_UNIT_TEST(test_ch_new_session_fails),
        CH_UNIT_TEST(test_ch_fill_random_fails),
        CH_UNIT_TEST(test_ch_rand_bytes_fails),
        CH_UNIT_TEST(test_ch_cipher_list_fails),
        CH_UNIT_TEST(test_ch_extensions_fail),
        CH_UNIT_TEST(test_ch_dtls_cookie_too_long),
        CH_UNIT_TEST(test_ch_wpkt_client_version_fails),
        CH_UNIT_TEST(test_ch_wpkt_random_memcpy_fails),
        CH_UNIT_TEST(test_ch_wpkt_session_id_open_fails),
        CH_UNIT_TEST(test_ch_wpkt_session_id_memcpy_fails),
        CH_UNIT_TEST(test_ch_wpkt_session_id_close_fails),
        CH_UNIT_TEST(test_ch_wpkt_dtls_cookie_fails),
        CH_UNIT_TEST(test_ch_wpkt_ciphers_open_fails),
        CH_UNIT_TEST(test_ch_wpkt_ciphers_close_fails),
        CH_UNIT_TEST(test_ch_wpkt_compression_open_fails),
        CH_UNIT_TEST(test_ch_wpkt_compression_null_fails),
        CH_UNIT_TEST(test_ch_wpkt_compression_close_fails),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
