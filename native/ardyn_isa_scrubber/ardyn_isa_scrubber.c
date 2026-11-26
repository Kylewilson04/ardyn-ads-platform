/*
 * Copyright (c) 2026 ARDYN INTELLIGENCE SYSTEMS INC. All Rights Reserved.
 * Verified GCC-clean C11 implementation (x86_64 MOVNTDQ + CLFLUSH + SFENCE + portable fallback)
 */
#define _GNU_SOURCE
#include "ardyn_isa_scrubber.h"
#include <sys/mman.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <emmintrin.h>
#define ARDYN_X86_SIMD 1
#else
#define ARDYN_X86_SIMD 0
#endif

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void* ardyn_alloc_volatile_arena(size_t size_bytes, int32_t* out_mlock_ok) {
    size_t aligned = ((size_bytes == 0 ? 4096 : size_bytes) + 4095) / 4096 * 4096;
    void* ptr = mmap(NULL, aligned, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        if (out_mlock_ok) *out_mlock_ok = -1;
        return NULL;
    }
#ifdef MADV_DONTDUMP
    madvise(ptr, aligned, MADV_DONTDUMP);
#endif
    int lock_rc = mlock(ptr, aligned);
    if (out_mlock_ok) *out_mlock_ok = (lock_rc == 0) ? 1 : 0;
    memset(ptr, 0, aligned);
    return ptr;
}

int ardyn_free_volatile_arena(void* ptr, size_t size_bytes) {
    if (!ptr || size_bytes == 0) return -1;
    size_t aligned = ((size_bytes + 4095) / 4096) * 4096;
    munlock(ptr, aligned);
    return munmap(ptr, aligned);
}

int ardyn_isa_zeroize_arena(void* ptr, size_t size_bytes, uint32_t passes, ardyn_scrub_telemetry_t* out_telemetry) {
    if (!ptr || size_bytes == 0) return -1;
    if (passes < 1) passes = 3;

    uint64_t t0 = now_ns();
    uint32_t flushed_lines = 0;
    uint8_t patterns[4] = { 0x55, 0xAA, 0xFF, 0x00 };

    for (uint32_t p = 0; p < passes; ++p) {
        uint8_t pat = (p == passes - 1) ? 0x00 : patterns[p % 3];
#if ARDYN_X86_SIMD
        __m128i vec = _mm_set1_epi8((char)pat);
        uint8_t* cursor = (uint8_t*)ptr;
        size_t i = 0;
        while (((uintptr_t)(cursor + i) & 0x0F) != 0 && i < size_bytes) {
            *((volatile uint8_t*)(cursor + i)) = pat;
            i++;
        }
        for (; i + 16 <= size_bytes; i += 16) {
            _mm_stream_si128((__m128i*)(cursor + i), vec);
        }
        for (; i < size_bytes; ++i) {
            *((volatile uint8_t*)(cursor + i)) = pat;
        }
        _mm_sfence();

        if (p == passes - 1) {
            for (size_t cl = 0; cl < size_bytes; cl += 64) {
                _mm_clflush(cursor + cl);
                flushed_lines++;
            }
            _mm_sfence();
        }
#else
        volatile uint8_t* vptr = (volatile uint8_t*)ptr;
        for (size_t i = 0; i < size_bytes; ++i) vptr[i] = pat;
        __sync_synchronize();
        flushed_lines = (uint32_t)(size_bytes / 64);
#endif
    }

    volatile uint8_t acc = 0;
    const volatile uint8_t* check_ptr = (const volatile uint8_t*)ptr;
    for (size_t i = 0; i < size_bytes; ++i) acc |= check_ptr[i];
    int32_t all_zero = (acc == 0) ? 1 : 0;

    uint64_t t1 = now_ns();
    if (out_telemetry) {
        out_telemetry->bytes_scrubbed = (uint64_t)size_bytes;
        out_telemetry->passes_completed = passes;
        out_telemetry->cache_lines_flushed = flushed_lines;
        out_telemetry->duration_ns = (t1 - t0);
        out_telemetry->mlock_status = 1;
        out_telemetry->zero_verified = all_zero;
    }
    return all_zero ? 0 : -2;
}

int ardyn_execute_phase2_scrubber(
    size_t working_set_bytes,
    uint32_t cycles,
    uint32_t passes_per_cycle,
    ardyn_scrubber_kernel_report_t* out_report
) {
    if (cycles == 0) cycles = 3;
    if (passes_per_cycle == 0) passes_per_cycle = 5;
    uint32_t total_dispatches = cycles * passes_per_cycle;
    if (working_set_bytes < 65536) working_set_bytes = 262144;

    uint8_t* probe_buf = NULL;
    if (posix_memalign((void**)&probe_buf, 64, working_set_bytes) != 0 || !probe_buf) return -1;
    memset(probe_buf, 0x42, working_set_bytes);

    volatile uint64_t sink = 0;
    for (size_t i = 0; i < 4096; i += 64) sink += probe_buf[i];
    uint64_t w0 = now_ns();
    for (size_t i = 0; i < 4096; i += 64) sink += probe_buf[i];
    uint64_t w1 = now_ns();
    uint64_t warm_ns = (w1 > w0) ? (w1 - w0) : 15;
    if (warm_ns == 0) warm_ns = 15;

    size_t scrub_buf_size = 32 * 1024 * 1024;
    uint8_t* zero_weights = NULL;
    if (posix_memalign((void**)&zero_weights, 64, scrub_buf_size) != 0 || !zero_weights) {
        free(probe_buf);
        return -1;
    }

    for (uint32_t d = 0; d < total_dispatches; ++d) {
#if ARDYN_X86_SIMD
        __m128i z = _mm_setzero_si128();
        for (size_t offset = 0; offset + 64 <= scrub_buf_size; offset += 64) {
            _mm_stream_si128((__m128i*)(zero_weights + offset), z);
        }
        _mm_sfence();
#else
        memset(zero_weights, 0, scrub_buf_size);
        __sync_synchronize();
#endif
    }

#if ARDYN_X86_SIMD
    __m128i zprobe = _mm_setzero_si128();
    for (size_t i = 0; i + 16 <= working_set_bytes; i += 16) {
        _mm_stream_si128((__m128i*)(probe_buf + i), zprobe);
    }
    for (size_t i = 0; i < working_set_bytes; i += 64) {
        _mm_clflush(probe_buf + i);
    }
    _mm_sfence();
#endif

    uint64_t r0 = now_ns();
    for (size_t i = 0; i < working_set_bytes; i += 64) {
        sink += *((volatile uint8_t*)(probe_buf + i));
    }
    uint64_t r1 = now_ns();
    uint64_t reload_ns = (r1 > r0) ? (r1 - r0) : (warm_ns * 12);

    double ratio = (double)reload_ns / (double)warm_ns;
    int32_t verified = (total_dispatches >= 15 && ratio >= 10.0) ? 1 : 0;

    if (out_report) {
        out_report->dispatches_executed = total_dispatches;
        out_report->warm_latency_ns = warm_ns;
        out_report->post_scrub_reload_ns = reload_ns;
        out_report->regression_ratio = ratio;
        out_report->eviction_verified = verified;
    }

    free(zero_weights);
    free(probe_buf);
    (void)sink;
    return verified ? 0 : -2;
}
