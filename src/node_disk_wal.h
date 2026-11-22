#ifndef NODE_DISK_WAL_H
#define NODE_DISK_WAL_H

#include "node.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if defined(NODE_HAVE_INFO_CODEC) && NODE_HAVE_INFO_CODEC
#include "info.h"
static info_codec_ws_t g_node_info_ws;
#endif

#define NODE_DISK_WAL_MAGIC  UINT32_C(0x4E57414C)
#define NODE_DISK_REC_BYTES  32U
#define NODE_DISK_SEG_RECS   32U
#define NODE_DISK_SNAP_BYTES 4096U

typedef struct {
    uint32_t records_written;
    uint32_t segments_written;
    uint32_t recovered_records;
    uint32_t torn_rejected;
    uint32_t raw_snap_bytes;
    uint32_t compressed_snap_bytes;
    uint32_t have_info_codec;
    bool roundtrip_exact;
    uint64_t chain_hash;
    uint64_t elapsed_us;
    bool passed;
} node_disk_wal_report_t;

static uint8_t g_disk_snap_raw[NODE_DISK_SNAP_BYTES];
static uint8_t g_disk_snap_comp[NODE_DISK_SNAP_BYTES * 2U];
static uint8_t g_disk_snap_decomp[NODE_DISK_SNAP_BYTES];
static uint8_t g_disk_seg_buf[NODE_DISK_SEG_RECS * NODE_DISK_REC_BYTES];

static uint64_t node_disk_now_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return UINT64_C(0);
    }
    return ((uint64_t)ts.tv_sec * UINT64_C(1000000)) + ((uint64_t)ts.tv_nsec / UINT64_C(1000));
}

static uint64_t node_disk_mix64(uint64_t prev_hash, uint32_t lsn, uint32_t tx_id, uint32_t key,
                                uint64_t val) {
    uint64_t x = prev_hash ^ UINT64_C(0x4E444457414C3031);
    x ^= ((uint64_t)lsn) | (((uint64_t)tx_id) << 32U);
    x = (x ^ (x >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
    x ^= ((uint64_t)key) + val;
    x = (x ^ (x >> 27U)) * UINT64_C(0x94D049BB133111EB);
    return x ^ (x >> 31U);
}

static void node_disk_wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & UINT32_C(0xFF));
    p[1] = (uint8_t)((v >> 8U) & UINT32_C(0xFF));
    p[2] = (uint8_t)((v >> 16U) & UINT32_C(0xFF));
    p[3] = (uint8_t)((v >> 24U) & UINT32_C(0xFF));
}

static uint32_t node_disk_rd32(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8U) | ((uint32_t)p[2] << 16U) |
           ((uint32_t)p[3] << 24U);
}

static void node_disk_wr64(uint8_t *p, uint64_t v) {
    for (uint32_t i = 0U; i < 8U; ++i) {
        p[i] = (uint8_t)((v >> (i * 8U)) & UINT64_C(0xFF));
    }
}

static uint64_t node_disk_rd64(const uint8_t *p) {
    uint64_t acc = UINT64_C(0);
    for (uint32_t i = 0U; i < 8U; ++i) {
        acc |= ((uint64_t)p[i]) << (i * 8U);
    }
    return acc;
}

#if !(defined(NODE_HAVE_INFO_CODEC) && NODE_HAVE_INFO_CODEC)
static size_t node_rle_compress_fallback(const uint8_t *src, size_t src_len, uint8_t *dst,
                                         size_t dst_cap) {
    size_t i = 0U;
    size_t o = 0U;
    while (i < src_len) {
        uint8_t b = src[i];
        size_t run = 1U;
        while ((i + run) < src_len && src[i + run] == b && run < 255U) {
            run++;
        }
        if (o + 2U > dst_cap) {
            return 0U;
        }
        dst[o++] = (uint8_t)run;
        dst[o++] = b;
        i += run;
    }
    return o;
}

static size_t node_rle_decompress_fallback(const uint8_t *src, size_t src_len, uint8_t *dst,
                                           size_t dst_cap) {
    size_t i = 0U;
    size_t o = 0U;
    while (i + 1U < src_len) {
        uint8_t cnt = src[i++];
        uint8_t val = src[i++];
        for (uint8_t k = 0U; k < cnt; ++k) {
            if (o >= dst_cap) {
                return 0U;
            }
            dst[o++] = val;
        }
    }
    return o;
}
#endif

static bool node_host_disk_wal_run(const char *dir_path, uint32_t num_recs,
                                   node_disk_wal_report_t *out) {
    if (dir_path == NULL || out == NULL || num_recs < 4U || num_recs > 128U) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
        return false;
    }

    uint64_t t0 = node_disk_now_us();

    uint32_t n_segs = (num_recs + NODE_DISK_SEG_RECS - 1U) / NODE_DISK_SEG_RECS;
    uint64_t chain = UINT64_C(0x123456789ABCDEF0);
    uint32_t written = 0U;
    char path_buf[512];

    for (uint32_t seg = 0U; seg < n_segs; ++seg) {
        int nfmt = snprintf(path_buf, sizeof(path_buf), "%s/wal_%04u.log", dir_path, seg);
        if (nfmt <= 0 || (size_t)nfmt >= sizeof(path_buf)) {
            return false;
        }
        int fd = open(path_buf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            return false;
        }
        for (uint32_t k = 0U; k < NODE_DISK_SEG_RECS && written < num_recs; ++k) {
            uint8_t rec[NODE_DISK_REC_BYTES];
            uint32_t lsn = written;
            uint32_t tx_id = 100U + (written >> 2U);
            uint32_t key = (written & 7U);
            uint64_t val = ((uint64_t)(written + 1U) * UINT64_C(0x0001000000010001));
            chain = node_disk_mix64(chain, lsn, tx_id, key, val);

            node_disk_wr32(&rec[0], NODE_DISK_WAL_MAGIC);
            node_disk_wr32(&rec[4], lsn);
            node_disk_wr32(&rec[8], tx_id);
            node_disk_wr32(&rec[12], key);
            node_disk_wr64(&rec[16], val);
            node_disk_wr64(&rec[24], chain);

            ssize_t nw = write(fd, rec, sizeof(rec));
            if (nw != (ssize_t)sizeof(rec)) {
                (void)close(fd);
                return false;
            }
            written++;
        }
        /* Simulate mid-record crash on final segment via POSIX ftruncate */
        if (seg + 1U == n_segs) {
            off_t cur_sz = lseek(fd, (off_t)0, SEEK_END);
            if (cur_sz >= (off_t)NODE_DISK_REC_BYTES) {
                (void)ftruncate(fd, cur_sz - (off_t)13);
            }
        }
        if (fsync(fd) != 0) {
            (void)close(fd);
            return false;
        }
        (void)close(fd);
    }

    out->records_written = written;
    out->segments_written = n_segs;

    /* Phase 2: POSIX Crash Recovery & Torn-Tail Rejection */
    memset(g_disk_snap_raw, 0, sizeof(g_disk_snap_raw));
    uint64_t rec_chain = UINT64_C(0x123456789ABCDEF0);
    uint32_t recovered = 0U;
    uint32_t torn = 0U;
    bool stopped = false;

    for (uint32_t seg = 0U; seg < n_segs && !stopped; ++seg) {
        (void)snprintf(path_buf, sizeof(path_buf), "%s/wal_%04u.log", dir_path, seg);
        int fd = open(path_buf, O_RDONLY);
        if (fd < 0) {
            return false;
        }
        ssize_t nread = read(fd, g_disk_seg_buf, sizeof(g_disk_seg_buf));
        (void)close(fd);
        if (nread < 0) {
            return false;
        }
        size_t full_bytes = ((size_t)nread / NODE_DISK_REC_BYTES) * NODE_DISK_REC_BYTES;
        if (full_bytes < (size_t)nread) {
            torn++;
        }
        for (size_t off = 0U; off < full_bytes; off += NODE_DISK_REC_BYTES) {
            const uint8_t *rp = &g_disk_seg_buf[off];
            if (node_disk_rd32(&rp[0]) != NODE_DISK_WAL_MAGIC) {
                torn++;
                stopped = true;
                break;
            }
            uint32_t lsn = node_disk_rd32(&rp[4]);
            uint32_t tx_id = node_disk_rd32(&rp[8]);
            uint32_t key = node_disk_rd32(&rp[12]);
            uint64_t val = node_disk_rd64(&rp[16]);
            uint64_t disk_hash = node_disk_rd64(&rp[24]);
            uint64_t exp_hash = node_disk_mix64(rec_chain, lsn, tx_id, key, val);
            if (lsn != recovered || disk_hash != exp_hash) {
                torn++;
                stopped = true;
                break;
            }
            rec_chain = exp_hash;
            if ((size_t)(recovered + 1U) * NODE_DISK_REC_BYTES <= NODE_DISK_SNAP_BYTES) {
                memcpy(&g_disk_snap_raw[(size_t)recovered * NODE_DISK_REC_BYTES], rp,
                       NODE_DISK_REC_BYTES);
            }
            recovered++;
        }
    }

    out->recovered_records = recovered;
    out->torn_rejected = torn;
    out->chain_hash = rec_chain;
    out->raw_snap_bytes = NODE_DISK_SNAP_BYTES;

    /* Phase 3: Zero-Heap Snapshot Compression (../INFO/build/libinfo.a or RLE fallback) */
    size_t comp_len = 0U;
    size_t decomp_len = 0U;
    memset(g_disk_snap_comp, 0, sizeof(g_disk_snap_comp));
    memset(g_disk_snap_decomp, 0, sizeof(g_disk_snap_decomp));

#if defined(NODE_HAVE_INFO_CODEC) && NODE_HAVE_INFO_CODEC
    out->have_info_codec = 1U;
    info_ws_reset(&g_node_info_ws);
    comp_len =
        info_compress(&g_node_info_ws, g_disk_snap_raw, NODE_DISK_SNAP_BYTES, g_disk_snap_comp,
                      sizeof(g_disk_snap_comp), INFO_CODEC_FLAG_ALG | INFO_LANG_RAW);
    if (comp_len > 0U) {
        info_ws_reset(&g_node_info_ws);
        decomp_len = info_decompress(&g_node_info_ws, g_disk_snap_comp, comp_len,
                                     g_disk_snap_decomp, sizeof(g_disk_snap_decomp));
    }
#else
    out->have_info_codec = 0U;
    comp_len = node_rle_compress_fallback(g_disk_snap_raw, NODE_DISK_SNAP_BYTES, g_disk_snap_comp,
                                          sizeof(g_disk_snap_comp));
    if (comp_len > 0U) {
        decomp_len = node_rle_decompress_fallback(g_disk_snap_comp, comp_len, g_disk_snap_decomp,
                                                  sizeof(g_disk_snap_decomp));
    }
#endif

    out->compressed_snap_bytes = (uint32_t)comp_len;
    out->roundtrip_exact = (comp_len > 0U && decomp_len == NODE_DISK_SNAP_BYTES &&
                            memcmp(g_disk_snap_raw, g_disk_snap_decomp, NODE_DISK_SNAP_BYTES) == 0);

    if (out->roundtrip_exact) {
        (void)snprintf(path_buf, sizeof(path_buf), "%s/snap_0001.inf1", dir_path);
        int sfd = open(path_buf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (sfd >= 0) {
            (void)write(sfd, g_disk_snap_comp, comp_len);
            (void)fsync(sfd);
            (void)close(sfd);
        }
    }

    uint64_t t1 = node_disk_now_us();
    out->elapsed_us = (t1 > t0) ? (t1 - t0) : UINT64_C(1);
    out->passed = (out->recovered_records == num_recs - 1U && out->torn_rejected >= 1U &&
                   out->roundtrip_exact);
    return out->passed;
}

#endif /* NODE_DISK_WAL_H */
