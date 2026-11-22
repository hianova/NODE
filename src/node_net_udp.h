#ifndef NODE_NET_UDP_H
#define NODE_NET_UDP_H

#include "node.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    uint32_t sent_ok;
    uint32_t recv_ok;
    uint32_t replay_rejected;
    uint32_t tamper_rejected;
    uint32_t post_attack_ok;
    uint16_t port;
    uint64_t session_key;
    uint64_t elapsed_us;
    bool passed;
} node_udp_bench_report_t;

static uint64_t node_host_udp_now_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return UINT64_C(0);
    }
    return ((uint64_t)ts.tv_sec * UINT64_C(1000000)) + ((uint64_t)ts.tv_nsec / UINT64_C(1000));
}

static bool node_host_udp_loopback_run(uint32_t count, node_udp_bench_report_t *out) {
    if (out == NULL || count == 0U || count > 4096U) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    int rx_fd = socket(AF_INET, SOCK_DGRAM, 0);
    int tx_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rx_fd < 0 || tx_fd < 0) {
        if (rx_fd >= 0)
            (void)close(rx_fd);
        if (tx_fd >= 0)
            (void)close(tx_fd);
        return false;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    (void)setsockopt(rx_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, (socklen_t)sizeof(tv));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl((uint32_t)INADDR_LOOPBACK);
    bind_addr.sin_port = htons((uint16_t)0U);
    if (bind(rx_fd, (const struct sockaddr *)&bind_addr, (socklen_t)sizeof(bind_addr)) != 0) {
        (void)close(rx_fd);
        (void)close(tx_fd);
        return false;
    }

    struct sockaddr_in bound_addr;
    memset(&bound_addr, 0, sizeof(bound_addr));
    socklen_t bound_len = (socklen_t)sizeof(bound_addr);
    if (getsockname(rx_fd, (struct sockaddr *)&bound_addr, &bound_len) != 0) {
        (void)close(rx_fd);
        (void)close(tx_fd);
        return false;
    }
    out->port = ntohs(bound_addr.sin_port);

    uint64_t psk = UINT64_C(0x9E3779B97F4A7C15);
    uint32_t id_a = UINT32_C(101);
    uint32_t id_b = UINT32_C(202);
    uint64_t nonce_a = UINT64_C(0x1122334455667788);
    uint64_t nonce_b = UINT64_C(0xAABBCCDDEEFF0011);
    uint32_t epoch = UINT32_C(7);
    uint64_t sk_a = node_session_derive_key(psk, id_a, id_b, nonce_a, nonce_b, epoch, 0x03U, 0x02U);
    uint64_t sk_b = node_session_derive_key(psk, id_a, id_b, nonce_a, nonce_b, epoch, 0x03U, 0x02U);
    if (sk_a != sk_b || sk_a == UINT64_C(0)) {
        (void)close(rx_fd);
        (void)close(tx_fd);
        return false;
    }
    out->session_key = sk_a;

    node_replay_win_t rx_win;
    node_replay_win_init(&rx_win, epoch);

    uint8_t tx_buf[NODE_WIRE_HDR_BYTES + NODE_WIRE_MAX_PAYLOAD];
    uint8_t rx_buf[NODE_WIRE_HDR_BYTES + NODE_WIRE_MAX_PAYLOAD];
    uint8_t replay_pkt[NODE_WIRE_HDR_BYTES + NODE_WIRE_MAX_PAYLOAD];
    size_t replay_len = 0U;
    uint8_t payload[32];
    uint8_t recv_payload[NODE_WIRE_MAX_PAYLOAD];

    uint64_t t0 = node_host_udp_now_us();

    for (uint32_t seq = 1U; seq <= count; ++seq) {
        memset(payload, 0, sizeof(payload));
        payload[0] = (uint8_t)(seq & 0xFFU);
        payload[1] = (uint8_t)((seq >> 8U) & 0xFFU);
        payload[2] = UINT8_C(0x4E);
        payload[3] = UINT8_C(0x32);

        size_t flen = node_net_wire_frame_encode(sk_a, epoch, (uint64_t)seq, 0x03U, 0x02U, payload,
                                                 sizeof(payload), tx_buf, sizeof(tx_buf));
        if (flen == 0U) {
            break;
        }
        ssize_t ntx = sendto(tx_fd, tx_buf, flen, 0, (const struct sockaddr *)&bound_addr,
                             (socklen_t)sizeof(bound_addr));
        if (ntx != (ssize_t)flen) {
            break;
        }
        out->sent_ok++;

        if (seq == count) {
            memcpy(replay_pkt, tx_buf, flen);
            replay_len = flen;
        }

        ssize_t nrx = recvfrom(rx_fd, rx_buf, sizeof(rx_buf), 0, NULL, NULL);
        if (nrx <= 0) {
            break;
        }
        size_t got_plen = 0U;
        uint64_t got_seq = UINT64_C(0);
        if (!node_net_wire_frame_decode_verify(sk_b, &rx_win, rx_buf, (size_t)nrx, recv_payload,
                                               sizeof(recv_payload), &got_plen, &got_seq)) {
            break;
        }
        if (got_plen == sizeof(payload) && got_seq == (uint64_t)seq &&
            memcmp(payload, recv_payload, sizeof(payload)) == 0) {
            out->recv_ok++;
        }
    }

    /* Active Dolev-Yao Replay Attack over 127.0.0.1 UDP socket */
    if (replay_len > 0U) {
        ssize_t rtx = sendto(tx_fd, replay_pkt, replay_len, 0, (const struct sockaddr *)&bound_addr,
                             (socklen_t)sizeof(bound_addr));
        if (rtx == (ssize_t)replay_len) {
            ssize_t rrx = recvfrom(rx_fd, rx_buf, sizeof(rx_buf), 0, NULL, NULL);
            if (rrx > 0) {
                size_t dummy_len = 0U;
                uint64_t dummy_seq = UINT64_C(0);
                if (!node_net_wire_frame_decode_verify(sk_b, &rx_win, rx_buf, (size_t)rrx,
                                                       recv_payload, sizeof(recv_payload),
                                                       &dummy_len, &dummy_seq)) {
                    out->replay_rejected = 1U;
                }
            }
        }
    }

    /* Active 1-Bit MAC Tamper Injection over 127.0.0.1 UDP socket */
    {
        memset(payload, 0x5A, sizeof(payload));
        size_t flen =
            node_net_wire_frame_encode(sk_a, epoch, (uint64_t)count + UINT64_C(1), 0x03U, 0x02U,
                                       payload, sizeof(payload), tx_buf, sizeof(tx_buf));
        if (flen >= NODE_WIRE_HDR_BYTES) {
            tx_buf[NODE_WIRE_HDR_BYTES - 1U] ^= UINT8_C(0x01);
            ssize_t ttx = sendto(tx_fd, tx_buf, flen, 0, (const struct sockaddr *)&bound_addr,
                                 (socklen_t)sizeof(bound_addr));
            if (ttx == (ssize_t)flen) {
                ssize_t trx = recvfrom(rx_fd, rx_buf, sizeof(rx_buf), 0, NULL, NULL);
                if (trx > 0) {
                    size_t dummy_len = 0U;
                    uint64_t dummy_seq = UINT64_C(0);
                    if (!node_net_wire_frame_decode_verify(sk_b, &rx_win, rx_buf, (size_t)trx,
                                                           recv_payload, sizeof(recv_payload),
                                                           &dummy_len, &dummy_seq)) {
                        out->tamper_rejected = 1U;
                    }
                }
            }
        }
    }

    /* Genuine follow-up frame must still pass after attack rejection */
    {
        memset(payload, 0x77, sizeof(payload));
        size_t flen =
            node_net_wire_frame_encode(sk_a, epoch, (uint64_t)count + UINT64_C(2), 0x03U, 0x02U,
                                       payload, sizeof(payload), tx_buf, sizeof(tx_buf));
        if (flen > 0U) {
            ssize_t ptx = sendto(tx_fd, tx_buf, flen, 0, (const struct sockaddr *)&bound_addr,
                                 (socklen_t)sizeof(bound_addr));
            if (ptx == (ssize_t)flen) {
                ssize_t prx = recvfrom(rx_fd, rx_buf, sizeof(rx_buf), 0, NULL, NULL);
                if (prx > 0) {
                    size_t dummy_len = 0U;
                    uint64_t dummy_seq = UINT64_C(0);
                    if (node_net_wire_frame_decode_verify(sk_b, &rx_win, rx_buf, (size_t)prx,
                                                          recv_payload, sizeof(recv_payload),
                                                          &dummy_len, &dummy_seq) &&
                        dummy_seq == (uint64_t)count + UINT64_C(2)) {
                        out->post_attack_ok = 1U;
                    }
                }
            }
        }
    }

    uint64_t t1 = node_host_udp_now_us();
    out->elapsed_us = (t1 > t0) ? (t1 - t0) : UINT64_C(1);

    (void)close(rx_fd);
    (void)close(tx_fd);

    out->passed = (out->sent_ok == count && out->recv_ok == count && out->replay_rejected == 1U &&
                   out->tamper_rejected == 1U && out->post_attack_ok == 1U);
    return out->passed;
}

#endif /* NODE_NET_UDP_H */
