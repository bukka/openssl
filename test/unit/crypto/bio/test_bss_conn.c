/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_NO_SOCK

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <cmocka.h>
#include "bio_local.h"

/*
 * Redeclare the private struct so we can inspect and pre-seed fields.
 * Must mirror bio_connect_st in bss_conn.c exactly, including the KTLS
 * conditional, so field offsets match.
 */
typedef struct bio_connect_st {
    int state;
    int connect_family;
    int connect_sock_type;
    char *param_hostname;
    char *param_service;
    int connect_mode;
#ifndef OPENSSL_NO_KTLS
    unsigned char record_type;
#endif
    int tfo_first;
    BIO_ADDRINFO *addr_first;
    const BIO_ADDRINFO *addr_iter;
    BIO_info_cb *info_callback;
    BIO *dgram_bio;
} BIO_CONNECT;

#define BIO_CONN_S_BEFORE 1
#define BIO_CONN_S_GET_ADDR 2
#define BIO_CONN_S_CREATE_SOCKET 3
#define BIO_CONN_S_CONNECT 4
#define BIO_CONN_S_OK 5
#define BIO_CONN_S_BLOCKED_CONNECT 6
#define BIO_CONN_S_CONNECT_ERROR 7

#define FAKE_SOCKET 42

/*
 * Fake addrinfo used across state machine tests.  g_addrinfo1.bai_next is
 * NULL by default.  Tests needing a second address temporarily set it to
 * &g_addrinfo2 and restore it afterwards.
 */
static struct sockaddr_in g_sin;
static BIO_ADDRINFO g_addrinfo1;
static BIO_ADDRINFO g_addrinfo2;

/* prototypes for __wrap_* (required by -Wmissing-prototypes) */
ssize_t __wrap_read(int fd, void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count);
int __wrap_shutdown(int sockfd, int how);
int __wrap_BIO_lookup(const char *host, const char *service,
    enum BIO_lookup_type lookup_type,
    int family, int socktype, BIO_ADDRINFO **res);
int __wrap_BIO_socket(int domain, int socktype, int protocol, int options);
int __wrap_BIO_connect(int sock, const BIO_ADDR *addr, int options);
int __wrap_BIO_sock_should_retry(int i);
int __wrap_BIO_closesocket(int sock);
int __wrap_BIO_socket_wait(int fd, int for_write, time_t max_time);
int __wrap_BIO_sock_error(int sock);

/* wraps */

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    function_called();
    check_expected(fd);
    check_expected_ptr(buf);
    check_expected(count);
    return mock_type(ssize_t);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    function_called();
    check_expected(fd);
    check_expected_ptr(buf);
    check_expected(count);
    return mock_type(ssize_t);
}

int __wrap_shutdown(int sockfd, int how)
{
    function_called();
    check_expected(sockfd);
    check_expected(how);
    return mock_type(int);
}

int __wrap_BIO_lookup(const char *host, const char *service,
    enum BIO_lookup_type lookup_type,
    int family, int socktype, BIO_ADDRINFO **res)
{
    int rc;

    function_called();
    check_expected(host);
    check_expected(service);
    check_expected(lookup_type);
    check_expected(family);
    check_expected(socktype);
    rc = mock_type(int);
    if (rc == 1)
        *res = mock_ptr_type(BIO_ADDRINFO *);
    return rc;
}

int __wrap_BIO_socket(int domain, int socktype, int protocol, int options)
{
    function_called();
    check_expected(domain);
    check_expected(socktype);
    check_expected(protocol);
    check_expected(options);
    return mock_type(int);
}

int __wrap_BIO_connect(int sock, const BIO_ADDR *addr, int options)
{
    function_called();
    check_expected(sock);
    check_expected_ptr(addr);
    check_expected(options);
    return mock_type(int);
}

/*
 * BIO_sock_should_retry is wrapped rather than controlled via errno because
 * mocked BIO_connect returning 0 does not naturally set socket errno.
 */
int __wrap_BIO_sock_should_retry(int i)
{
    function_called();
    check_expected(i);
    return mock_type(int);
}

int __wrap_BIO_closesocket(int sock)
{
    function_called();
    check_expected(sock);
    return mock_type(int);
}

int __wrap_BIO_socket_wait(int fd, int for_write, time_t max_time)
{
    function_called();
    check_expected(fd);
    check_expected(for_write);
    (void)max_time; /* derived from time(NULL): not checked */
    return mock_type(int);
}

int __wrap_BIO_sock_error(int sock)
{
    function_called();
    check_expected(sock);
    return mock_type(int);
}

/* expectations */

static void expect_read(int fd, const void *buf, size_t count, ssize_t rc)
{
    expect_function_call(__wrap_read);
    expect_value(__wrap_read, fd, fd);
    expect_value(__wrap_read, buf, buf);
    expect_value(__wrap_read, count, count);
    will_return(__wrap_read, rc);
}

static void expect_write(int fd, const void *buf, size_t count, ssize_t rc)
{
    expect_function_call(__wrap_write);
    expect_value(__wrap_write, fd, fd);
    expect_value(__wrap_write, buf, buf);
    expect_value(__wrap_write, count, count);
    will_return(__wrap_write, rc);
}

static void expect_shutdown(int sockfd, int how, int rc)
{
    expect_function_call(__wrap_shutdown);
    expect_value(__wrap_shutdown, sockfd, sockfd);
    expect_value(__wrap_shutdown, how, how);
    will_return(__wrap_shutdown, rc);
}

static void expect_BIO_lookup(BIO_ADDRINFO *res, int rc)
{
    expect_function_call(__wrap_BIO_lookup);
    expect_any(__wrap_BIO_lookup, host);
    expect_any(__wrap_BIO_lookup, service);
    expect_any(__wrap_BIO_lookup, lookup_type);
    expect_any(__wrap_BIO_lookup, family);
    expect_any(__wrap_BIO_lookup, socktype);
    will_return(__wrap_BIO_lookup, rc);
    if (rc == 1)
        will_return(__wrap_BIO_lookup, res);
}

static void expect_BIO_socket(int domain, int socktype, int protocol, int rc)
{
    expect_function_call(__wrap_BIO_socket);
    expect_value(__wrap_BIO_socket, domain, domain);
    expect_value(__wrap_BIO_socket, socktype, socktype);
    expect_value(__wrap_BIO_socket, protocol, protocol);
    expect_any(__wrap_BIO_socket, options);
    will_return(__wrap_BIO_socket, rc);
}

static void expect_BIO_connect(int sock, const BIO_ADDR *addr, int rc)
{
    expect_function_call(__wrap_BIO_connect);
    expect_value(__wrap_BIO_connect, sock, sock);
    expect_value(__wrap_BIO_connect, addr, addr);
    expect_any(__wrap_BIO_connect, options);
    will_return(__wrap_BIO_connect, rc);
}

static void expect_BIO_sock_should_retry(int i, int rc)
{
    expect_function_call(__wrap_BIO_sock_should_retry);
    expect_value(__wrap_BIO_sock_should_retry, i, i);
    will_return(__wrap_BIO_sock_should_retry, rc);
}

static void expect_BIO_closesocket(int sock, int rc)
{
    expect_function_call(__wrap_BIO_closesocket);
    expect_value(__wrap_BIO_closesocket, sock, sock);
    will_return(__wrap_BIO_closesocket, rc);
}

static void expect_BIO_socket_wait(int fd, int for_write, int rc)
{
    expect_function_call(__wrap_BIO_socket_wait);
    expect_value(__wrap_BIO_socket_wait, fd, fd);
    expect_value(__wrap_BIO_socket_wait, for_write, for_write);
    will_return(__wrap_BIO_socket_wait, rc);
}

static void expect_BIO_sock_error(int sock, int rc)
{
    expect_function_call(__wrap_BIO_sock_error);
    expect_value(__wrap_BIO_sock_error, sock, sock);
    will_return(__wrap_BIO_sock_error, rc);
}

/* helpers */

static BIO_CONNECT *get_data(BIO *bio)
{
    return (BIO_CONNECT *)bio->ptr;
}

/*
 * Call at the end of any test that sets bio->num or addr_first to prevent
 * unexpected BIO_closesocket or BIO_ADDRINFO_free invocations in teardown.
 */
static void reset_for_teardown(BIO *bio)
{
    BIO_CONNECT *data = get_data(bio);

    bio->num = (int)INVALID_SOCKET;
    data->addr_first = NULL;
    data->addr_iter = NULL;
    data->state = BIO_CONN_S_BEFORE;
}

/* setup / teardown */

static int setup(void **state)
{
    BIO *bio = BIO_new(BIO_s_connect());

    assert_non_null(bio);
    *state = bio;
    return 0;
}

static int teardown(void **state)
{
    if (*state != NULL)
        BIO_free(*state);
    return 0;
}

/* I/O tests pre-establish state=OK so the state machine is not entered. */
static int setup_io(void **state)
{
    BIO *bio;
    BIO_CONNECT *data;

    if (setup(state) != 0)
        return -1;
    bio = *state;
    data = get_data(bio);
    data->state = BIO_CONN_S_OK;
    bio->num = FAKE_SOCKET;
    return 0;
}

static int teardown_io(void **state)
{
    if (*state != NULL)
        reset_for_teardown(*state);
    return teardown(state);
}

static int group_setup(void **state)
{
    (void)state;

    memset(&g_sin, 0, sizeof(g_sin));
    g_sin.sin_family = AF_INET;
    g_sin.sin_port = htons(443);
    g_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    memset(&g_addrinfo1, 0, sizeof(g_addrinfo1));
    g_addrinfo1.bai_family = AF_INET;
    g_addrinfo1.bai_socktype = SOCK_STREAM;
    g_addrinfo1.bai_protocol = IPPROTO_TCP;
    g_addrinfo1.bai_addrlen = sizeof(g_sin);
    g_addrinfo1.bai_addr = (struct sockaddr *)&g_sin;
    g_addrinfo1.bai_next = NULL;

    memcpy(&g_addrinfo2, &g_addrinfo1, sizeof(g_addrinfo1));
    g_addrinfo2.bai_next = NULL;

    return 0;
}

/* conn_new */

static void test_conn_new(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    assert_non_null(data);
    assert_int_equal(data->state, BIO_CONN_S_BEFORE);
    assert_int_equal(data->connect_family, BIO_FAMILY_IPANY);
    assert_int_equal(data->connect_sock_type, SOCK_STREAM);
    assert_null(data->param_hostname);
    assert_null(data->param_service);
    assert_null(data->addr_first);
    assert_null(data->dgram_bio);
    assert_int_equal(bio->num, (int)INVALID_SOCKET);
    assert_int_equal(bio->init, 0);
}

/* conn_free */

static void test_conn_free_no_shutdown(void **state)
{
    /* shutdown=0: conn_close_socket and BIO_CONNECT_free are both skipped */
    BIO *bio = BIO_new(BIO_s_connect());

    assert_non_null(bio);
    bio->shutdown = BIO_NOCLOSE;
    BIO_free(bio);
    *state = NULL;
}

/* conn_close_socket (via BIO_CTRL_RESET) */

static void test_close_socket_none(void **state)
{
    /* bio->num == INVALID_SOCKET: no calls expected */
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_RESET, 0, NULL), 0);
}

static void test_close_socket_non_ok_state(void **state)
{
    /* Socket open but state != OK: BIO_closesocket called, no shutdown */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    bio->num = FAKE_SOCKET;
    data->state = BIO_CONN_S_BLOCKED_CONNECT;

    expect_BIO_closesocket(FAKE_SOCKET, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL), 0);
    assert_int_equal(bio->num, (int)INVALID_SOCKET);
    assert_int_equal(data->state, BIO_CONN_S_BEFORE);
}

static void test_close_socket_ok_state(void **state)
{
    /* Socket open and state=OK: shutdown first, then BIO_closesocket */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    bio->num = FAKE_SOCKET;
    data->state = BIO_CONN_S_OK;

    expect_shutdown(FAKE_SOCKET, 2, 0);
    expect_BIO_closesocket(FAKE_SOCKET, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL), 0);
    assert_int_equal(bio->num, (int)INVALID_SOCKET);
    assert_int_equal(data->state, BIO_CONN_S_BEFORE);
}

/* conn_state (via BIO_C_DO_STATE_MACHINE) */

static void test_conn_state_no_hostname(void **state)
{
    /* BEFORE with no hostname and no service */
    assert_true(BIO_ctrl(*state, BIO_C_DO_STATE_MACHINE, 0, NULL) <= 0);
}

static void test_conn_state_unsupported_family(void **state)
{
    /* BEFORE -> GET_ADDR -> unrecognised connect_family -> error */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->param_hostname = OPENSSL_strdup("host");
    data->param_service = OPENSSL_strdup("443");
    data->connect_family = 9999;

    assert_true(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL) <= 0);
}

static void test_conn_state_lookup_fails(void **state)
{
    /* BEFORE -> GET_ADDR -> BIO_lookup returns 0 */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->param_hostname = OPENSSL_strdup("host");
    data->param_service = OPENSSL_strdup("443");

    expect_BIO_lookup(NULL, 0);
    assert_true(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL) <= 0);
}

static void test_conn_state_socket_fails(void **state)
{
    /* Pre-set CREATE_SOCKET: BIO_socket returns INVALID_SOCKET */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_CREATE_SOCKET;
    data->addr_iter = &g_addrinfo1;

    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP,
        (int)INVALID_SOCKET);
    assert_true(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL) <= 0);

    data->addr_iter = NULL;
    data->state = BIO_CONN_S_BEFORE;
}

static void test_conn_state_connect_succeeds(void **state)
{
    /* Full happy path: BEFORE -> GET_ADDR -> CREATE_SOCKET -> CONNECT -> OK */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->param_hostname = OPENSSL_strdup("host");
    data->param_service = OPENSSL_strdup("443");

    expect_BIO_lookup(&g_addrinfo1, 1);
    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, FAKE_SOCKET);
    expect_BIO_connect(FAKE_SOCKET, (BIO_ADDR *)&g_sin, 1);

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 1);
    assert_int_equal(data->state, BIO_CONN_S_OK);

    reset_for_teardown(bio);
}

static void test_conn_state_already_ok(void **state)
{
    /* State already OK: returns 1 with no external calls */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_OK;
    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 1);
    data->state = BIO_CONN_S_BEFORE;
}

static void test_conn_state_connect_retry(void **state)
{
    /* Pre-set CONNECT: BIO_connect fails with retry -> BLOCKED_CONNECT */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_CONNECT;
    data->addr_iter = &g_addrinfo1;
    bio->num = FAKE_SOCKET;

    expect_BIO_connect(FAKE_SOCKET, (BIO_ADDR *)&g_sin, 0);
    expect_BIO_sock_should_retry(0, 1);

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 0);
    assert_int_equal(data->state, BIO_CONN_S_BLOCKED_CONNECT);
    assert_int_equal(bio->retry_reason, BIO_RR_CONNECT);

    reset_for_teardown(bio);
}

static void test_conn_state_connect_error(void **state)
{
    /* Pre-set CONNECT: fails, no retry, no more addresses -> CONNECT_ERROR */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_CONNECT;
    data->addr_iter = &g_addrinfo1; /* bai_next == NULL */
    bio->num = FAKE_SOCKET;

    expect_BIO_connect(FAKE_SOCKET, (BIO_ADDR *)&g_sin, 0);
    expect_BIO_sock_should_retry(0, 0);
    /* loop continues to CONNECT_ERROR which exits immediately */

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 0);

    reset_for_teardown(bio);
}

static void test_conn_state_connect_next_addr(void **state)
{
    /*
     * Pre-set CONNECT with two addresses: first connect fails, iterator
     * advances, second CREATE_SOCKET fails so we get a clean exit.
     */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    g_addrinfo1.bai_next = &g_addrinfo2;
    data->state = BIO_CONN_S_CONNECT;
    data->addr_iter = &g_addrinfo1;
    bio->num = FAKE_SOCKET;

    expect_BIO_connect(FAKE_SOCKET, (BIO_ADDR *)&g_sin, 0);
    expect_BIO_sock_should_retry(0, 0);
    expect_BIO_closesocket(FAKE_SOCKET, 0);
    /* CREATE_SOCKET for g_addrinfo2 */
    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP,
        (int)INVALID_SOCKET);

    assert_true(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL) <= 0);

    g_addrinfo1.bai_next = NULL;
    reset_for_teardown(bio);
}

static void test_conn_state_blocked_ok(void **state)
{
    /* Pre-set BLOCKED_CONNECT: socket becomes writable, no error -> OK */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_BLOCKED_CONNECT;
    data->addr_iter = &g_addrinfo1;
    bio->num = FAKE_SOCKET;

    expect_BIO_socket_wait(FAKE_SOCKET, 0, 1);
    expect_BIO_sock_error(FAKE_SOCKET, 0);

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 1);
    assert_int_equal(data->state, BIO_CONN_S_OK);

    reset_for_teardown(bio);
}

static void test_conn_state_blocked_error(void **state)
{
    /* Pre-set BLOCKED_CONNECT: socket error, no more addresses -> error */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_BLOCKED_CONNECT;
    data->addr_iter = &g_addrinfo1; /* bai_next == NULL */
    bio->num = FAKE_SOCKET;

    expect_BIO_socket_wait(FAKE_SOCKET, 0, 1);
    expect_BIO_sock_error(FAKE_SOCKET, ECONNREFUSED);

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 0);

    reset_for_teardown(bio);
}

/* conn_read */

static void test_conn_read_success(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 8, 8);
    assert_int_equal(BIO_read(bio, buf, 8), 8);
    assert_false(BIO_should_retry(bio));
    assert_false(BIO_eof(bio));
}

static void test_conn_read_eof(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 8, 0);
    expect_BIO_sock_should_retry(0, 0);
    assert_true(BIO_read(bio, buf, 8) <= 0);
    assert_true(BIO_eof(bio));
}

static void test_conn_read_retry(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 8, -1);
    expect_BIO_sock_should_retry(-1, 1);
    assert_true(BIO_read(bio, buf, 8) <= 0);
    assert_true(BIO_should_read(bio));
}

static void test_conn_read_error(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 8, -1);
    expect_BIO_sock_should_retry(-1, 0);
    assert_true(BIO_read(bio, buf, 8) <= 0);
    assert_false(BIO_should_retry(bio));
    assert_false(BIO_eof(bio));
}

/* conn_write */

static void test_conn_write_success(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_SOCKET, buf, 5, 5);
    assert_int_equal(BIO_write(bio, buf, 5), 5);
    assert_false(BIO_should_retry(bio));
}

static void test_conn_write_retry(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_SOCKET, buf, 5, -1);
    expect_BIO_sock_should_retry(-1, 1);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_true(BIO_should_write(bio));
}

static void test_conn_write_error(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_SOCKET, buf, 5, -1);
    expect_BIO_sock_should_retry(-1, 0);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_false(BIO_should_retry(bio));
}

/* conn_gets
 *
 * conn_gets is non-static (unlike the other method functions) so it is a
 * public symbol, but we exercise it via BIO_gets to stay in-interface.
 */

static void test_conn_gets_null_buf(void **state)
{
    assert_true(BIO_gets(*state, NULL, 8) <= 0);
}

static void test_conn_gets_zero_size(void **state)
{
    char buf[8] = { 0 };

    assert_true(BIO_gets(*state, buf, 0) <= 0);
}

static void test_conn_gets_null_ptr(void **state)
{
    /* bio->ptr == NULL is caught before any field access */
    BIO *bio = *state;
    char buf[8] = { 0 };
    void *saved = bio->ptr;

    bio->ptr = NULL;
    assert_true(BIO_gets(bio, buf, sizeof(buf)) <= 0);
    bio->ptr = saved;
}

static void test_conn_gets_dgram_bio_set(void **state)
{
    /* dgram_bio present is an error for gets */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    char buf[8] = { 0 };
    BIO fake_dgram;

    data->dgram_bio = &fake_dgram;
    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), -1);
    data->dgram_bio = NULL;
}

static void test_conn_gets_newline(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 'h', 'i', '\n' };

    expect_read(FAKE_SOCKET, buf, 1, 1);
    expect_read(FAKE_SOCKET, buf + 1, 1, 1);
    expect_read(FAKE_SOCKET, buf + 2, 1, 1);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 3);
    assert_memory_equal(buf, "hi\n", 4);
}

static void test_conn_gets_fills_buffer(void **state)
{
    /* size=4 allows at most 3 chars before the terminating NUL */
    BIO *bio = *state;
    char buf[4] = { 'a', 'b', 'c' };

    expect_read(FAKE_SOCKET, buf, 1, 1);
    expect_read(FAKE_SOCKET, buf + 1, 1, 1);
    expect_read(FAKE_SOCKET, buf + 2, 1, 1);

    assert_int_equal(BIO_gets(bio, buf, 4), 3);
    assert_memory_equal(buf, "abc", 4);
}

static void test_conn_gets_eof_mid(void **state)
{
    /* One char read, then EOF: returns the char count */
    BIO *bio = *state;
    char buf[8] = { 'z' };

    expect_read(FAKE_SOCKET, buf, 1, 1);
    expect_read(FAKE_SOCKET, buf + 1, 1, 0);
    expect_BIO_sock_should_retry(0, 0);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 1);
    assert_memory_equal(buf, "z", 2);
}

static void test_conn_gets_immediate_eof(void **state)
{
    /* First read returns 0: EOF flag set, returns 0 */
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 1, 0);
    expect_BIO_sock_should_retry(0, 0);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 0);
    assert_int_equal(buf[0], '\0');
}

static void test_conn_gets_retry(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 1, -1);
    expect_BIO_sock_should_retry(-1, 1);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), -1);
    assert_true(BIO_should_retry(bio));
}

/* conn_puts */

static void test_conn_puts_success(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_write(FAKE_SOCKET, str, 5, 5);
    assert_int_equal(BIO_puts(bio, str), 5);
}

static void test_conn_puts_write_fails(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_write(FAKE_SOCKET, str, 5, -1);
    expect_BIO_sock_should_retry(-1, 0);
    assert_true(BIO_puts(bio, str) <= 0);
}

/* conn_ctrl */

static void test_conn_ctrl_reset_no_socket(void **state)
{
    /* INVALID_SOCKET -> conn_close_socket is a no-op */
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_RESET, 0, NULL), 0);
    assert_int_equal(get_data(*state)->state, BIO_CONN_S_BEFORE);
}

static void test_conn_ctrl_get_connect(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    const char *out = NULL;

    /* NULL ptr always returns 0 regardless of num */
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 0, NULL), 0);

    data->param_hostname = OPENSSL_strdup("host.example");
    data->param_service = OPENSSL_strdup("443");
    data->connect_mode = BIO_SOCK_KEEPALIVE;

    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 0, &out), 1);
    assert_string_equal(out, "host.example");

    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 1, &out), 1);
    assert_string_equal(out, "443");

    /* num==4: connect_mode; ptr just needs to be non-NULL */
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 4, &out),
        BIO_SOCK_KEEPALIVE);

    /* unknown num with non-NULL ptr -> 0 */
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 99, &out), 0);
}

static void test_conn_ctrl_set_connect_hostname(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_CONNECT, 0, "host.example:443"),
        1);
    assert_int_equal(bio->init, 1);
    assert_string_equal(data->param_hostname, "host.example");
    assert_string_equal(data->param_service, "443");
}

static void test_conn_ctrl_set_connect_port(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_CONNECT, 1, "8443"), 1);
    assert_string_equal(data->param_service, "8443");
}

static void test_conn_ctrl_set_connect_family(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    int family = BIO_FAMILY_IPV4;

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_CONNECT, 3, &family), 1);
    assert_int_equal(data->connect_family, BIO_FAMILY_IPV4);
}

static void test_conn_ctrl_set_sock_type(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_SOCK_TYPE, SOCK_DGRAM, NULL), 1);
    assert_int_equal(data->connect_sock_type, SOCK_DGRAM);

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_SOCK_TYPE, SOCK_STREAM, NULL), 1);
    assert_int_equal(data->connect_sock_type, SOCK_STREAM);

    /* Invalid socktype */
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_SOCK_TYPE, 9999, NULL), 0);

    /* Too late once past BEFORE */
    data->state = BIO_CONN_S_GET_ADDR;
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_SOCK_TYPE, SOCK_DGRAM, NULL), 0);
    data->state = BIO_CONN_S_BEFORE;
}

static void test_conn_ctrl_get_sock_type(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->connect_sock_type = SOCK_DGRAM;
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_SOCK_TYPE, 0, NULL), SOCK_DGRAM);
    data->connect_sock_type = SOCK_STREAM;
}

static void test_conn_ctrl_get_dgram_bio(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO *out = NULL;
    BIO fake_dgram;

    /* dgram_bio NULL -> 0 */
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_DGRAM_BIO, 0, &out), 0);

    data->dgram_bio = &fake_dgram;
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_DGRAM_BIO, 0, &out), 1);
    assert_ptr_equal(out, &fake_dgram);
    data->dgram_bio = NULL;
}

static void test_conn_ctrl_nbio(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    BIO_ctrl(bio, BIO_C_SET_NBIO, 1, NULL);
    assert_true(data->connect_mode & BIO_SOCK_NONBLOCK);

    BIO_ctrl(bio, BIO_C_SET_NBIO, 0, NULL);
    assert_false(data->connect_mode & BIO_SOCK_NONBLOCK);
}

static void test_conn_ctrl_connect_mode(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    BIO_ctrl(bio, BIO_C_SET_CONNECT_MODE, BIO_SOCK_KEEPALIVE, NULL);
    assert_int_equal(data->connect_mode, BIO_SOCK_KEEPALIVE);
    assert_int_equal(data->tfo_first, 0);
}

static void test_conn_ctrl_get_fd(void **state)
{
    BIO *bio = *state;
    int fd = -1;

    /* init==0 -> -1 */
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_FD, 0, &fd), -1);

    bio->init = 1;
    bio->num = FAKE_SOCKET;
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_FD, 0, &fd), FAKE_SOCKET);
    assert_int_equal(fd, FAKE_SOCKET);

    bio->init = 0;
    bio->num = (int)INVALID_SOCKET;
}

static void test_conn_ctrl_get_set_close(void **state)
{
    BIO *bio = *state;

    bio->shutdown = BIO_NOCLOSE;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_GET_CLOSE, 0, NULL), BIO_NOCLOSE);

    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_CLOSE, NULL);
    assert_int_equal(bio->shutdown, BIO_CLOSE);
}

static void test_conn_ctrl_pending_flush(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL), 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL), 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL), 1);
}

static void test_conn_ctrl_eof(void **state)
{
    BIO *bio = *state;

    bio->flags &= ~BIO_FLAGS_IN_EOF;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 0);

    bio->flags |= BIO_FLAGS_IN_EOF;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 1);
    bio->flags &= ~BIO_FLAGS_IN_EOF;
}

static void test_conn_ctrl_default(void **state)
{
    assert_int_equal(BIO_ctrl(*state, 9999, 0, NULL), 0);
}

/* conn_callback_ctrl */

static int dummy_cb(BIO *b, int s, int res)
{
    (void)b;
    (void)s;
    return res;
}

static void test_conn_callback_ctrl_set(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO_info_cb *retrieved;

    /*
     * BIO_set_info_callback and BIO_get_info_callback are macros that cast
     * their return values to (int).  Wrap in (void) to suppress
     * -Wunused-value.
     */
    (void)BIO_set_info_callback(bio, dummy_cb);
    assert_ptr_equal(data->info_callback, dummy_cb);

    (void)BIO_get_info_callback(bio, &retrieved);
    assert_ptr_equal(retrieved, dummy_cb);

    (void)BIO_set_info_callback(bio, NULL);
}

static void test_conn_callback_ctrl_default(void **state)
{
    /* Unsupported cmd returns 0 */
    assert_int_equal(BIO_callback_ctrl(*state, 9999, dummy_cb), 0);
}

/* conn_sendmmsg / conn_recvmmsg */

static void test_conn_sendmmsg_no_dgram(void **state)
{
    /* State OK, dgram_bio NULL -> error */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO_MSG msg = { 0 };
    size_t processed = 1;

    data->state = BIO_CONN_S_OK;
    bio->num = FAKE_SOCKET;

    assert_int_equal(
        BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 0);
    assert_int_equal(processed, 0);

    reset_for_teardown(bio);
}

static void test_conn_recvmmsg_no_dgram(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO_MSG msg = { 0 };
    size_t processed = 1;

    data->state = BIO_CONN_S_OK;
    bio->num = FAKE_SOCKET;

    assert_int_equal(
        BIO_recvmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 0);
    assert_int_equal(processed, 0);

    reset_for_teardown(bio);
}

/* main */

#define CONN_TEST(name) \
    cmocka_unit_test_setup_teardown(name, setup, teardown)

#define CONN_TEST_IO(name) \
    cmocka_unit_test_setup_teardown(name, setup_io, teardown_io)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* conn_new */
        CONN_TEST(test_conn_new),
        /* conn_free */
        CONN_TEST(test_conn_free_no_shutdown),
        /* conn_close_socket */
        CONN_TEST(test_close_socket_none),
        CONN_TEST(test_close_socket_non_ok_state),
        CONN_TEST(test_close_socket_ok_state),
        /* conn_state */
        CONN_TEST(test_conn_state_no_hostname),
        CONN_TEST(test_conn_state_unsupported_family),
        CONN_TEST(test_conn_state_lookup_fails),
        CONN_TEST(test_conn_state_socket_fails),
        CONN_TEST(test_conn_state_connect_succeeds),
        CONN_TEST(test_conn_state_already_ok),
        CONN_TEST(test_conn_state_connect_retry),
        CONN_TEST(test_conn_state_connect_error),
        CONN_TEST(test_conn_state_connect_next_addr),
        CONN_TEST(test_conn_state_blocked_ok),
        CONN_TEST(test_conn_state_blocked_error),
        /* conn_read */
        CONN_TEST_IO(test_conn_read_success),
        CONN_TEST_IO(test_conn_read_eof),
        CONN_TEST_IO(test_conn_read_retry),
        CONN_TEST_IO(test_conn_read_error),
        /* conn_write */
        CONN_TEST_IO(test_conn_write_success),
        CONN_TEST_IO(test_conn_write_retry),
        CONN_TEST_IO(test_conn_write_error),
        /* conn_gets */
        CONN_TEST(test_conn_gets_null_buf),
        CONN_TEST(test_conn_gets_zero_size),
        CONN_TEST(test_conn_gets_null_ptr),
        CONN_TEST_IO(test_conn_gets_dgram_bio_set),
        CONN_TEST_IO(test_conn_gets_newline),
        CONN_TEST_IO(test_conn_gets_fills_buffer),
        CONN_TEST_IO(test_conn_gets_eof_mid),
        CONN_TEST_IO(test_conn_gets_immediate_eof),
        CONN_TEST_IO(test_conn_gets_retry),
        /* conn_puts */
        CONN_TEST_IO(test_conn_puts_success),
        CONN_TEST_IO(test_conn_puts_write_fails),
        /* conn_ctrl */
        CONN_TEST(test_conn_ctrl_reset_no_socket),
        CONN_TEST(test_conn_ctrl_get_connect),
        CONN_TEST(test_conn_ctrl_set_connect_hostname),
        CONN_TEST(test_conn_ctrl_set_connect_port),
        CONN_TEST(test_conn_ctrl_set_connect_family),
        CONN_TEST(test_conn_ctrl_set_sock_type),
        CONN_TEST(test_conn_ctrl_get_sock_type),
        CONN_TEST(test_conn_ctrl_get_dgram_bio),
        CONN_TEST(test_conn_ctrl_nbio),
        CONN_TEST(test_conn_ctrl_connect_mode),
        CONN_TEST(test_conn_ctrl_get_fd),
        CONN_TEST(test_conn_ctrl_get_set_close),
        CONN_TEST(test_conn_ctrl_pending_flush),
        CONN_TEST(test_conn_ctrl_eof),
        CONN_TEST(test_conn_ctrl_default),
        /* conn_callback_ctrl */
        CONN_TEST(test_conn_callback_ctrl_set),
        CONN_TEST(test_conn_callback_ctrl_default),
        /* conn_sendmmsg / conn_recvmmsg */
        CONN_TEST(test_conn_sendmmsg_no_dgram),
        CONN_TEST(test_conn_recvmmsg_no_dgram),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, group_setup, NULL);
}

#else

int main(void)
{
    return 0;
}

#endif /* OPENSSL_NO_SOCK */
