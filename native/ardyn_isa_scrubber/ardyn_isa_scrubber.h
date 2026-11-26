/*
 * Copyright (c) 2026 ARDYN INTELLIGENCE SYSTEMS INC. All Rights Reserved.
 * Hardware-Accelerated ISA Cache-Bypassing Volatile Memory Scrubber
 */
#ifndef ARDYN_ISA_SCRUBBER_H
#define ARDYN_ISA_SCRUBBER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t bytes_scrubbed;
    uint32_t passes_completed;
    uint32_t cache_lines_flushed;
    uint64_t duration_ns;
    int32_t  mlock_status;
    int32_t  zero_verified;
} ardyn_scrub_telemetry_t;

typedef struct {
    uint32_t dispatches_executed;
    uint64_t warm_latency_ns;
    uint64_t post_scrub_reload_ns;
    double   regression_ratio;
    int32_t  eviction_verified;
} ardyn_scrubber_kernel_report_t;

void* ardyn_alloc_volatile_arena(size_t size_bytes, int32_t* out_mlock_ok);
int   ardyn_free_volatile_arena(void* ptr, size_t size_bytes);
int   ardyn_isa_zeroize_arena(void* ptr, size_t size_bytes, uint32_t passes, ardyn_scrub_telemetry_t* out_telemetry);
int   ardyn_execute_phase2_scrubber(size_t working_set_bytes, uint32_t cycles, uint32_t passes_per_cycle, ardyn_scrubber_kernel_report_t* out_report);

#ifdef __cplusplus
}
#endif

#endif /* ARDYN_ISA_SCRUBBER_H */
