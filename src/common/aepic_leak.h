#pragma once

#include "utils.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <map>
#include <set>
#include <vector>

constexpr size_t NUMBER_INNER_LEAKS = 300;
constexpr size_t NUMBER_OUTER_LEAKS = 10;

constexpr uint8_t ATTACKER_LEAKER          = 2;
constexpr uint8_t ATTACKER_MEMORY_PRESSURE = 6;

// the number of maxima analysed in the leakage
constexpr size_t N_MAXIMA = 64;

// we leak an unsigned int
using leaked_value_t = uint32_t;

// each cache line
constexpr size_t LEAKED_VALUES_PER_LINE = 64 / sizeof(leaked_value_t);
using cache_line_t                      = std::array<leaked_value_t, LEAKED_VALUES_PER_LINE>;

// our targeted leak size
constexpr size_t APIC_LEAK_NUMBER_LINES = 2;
using leak_t                            = std::array<cache_line_t, APIC_LEAK_NUMBER_LINES>;

// we can leak 12 from 16 values per cache line
constexpr size_t APIC_LEAK_MAX = LEAKED_VALUES_PER_LINE * 3 / 4;

// we mark the data we want to leak and mask it so we can exclude self leakage
constexpr unsigned int MARK = 0x80808080;

// heatmap to postprocess the leak
struct heatmap_t {
    std::array<std::map<leaked_value_t, uint64_t>, APIC_LEAK_MAX> counts;
    std::array<std::vector<leaked_value_t>, APIC_LEAK_MAX>        values;
};

// scores to rank the most leaked rows
using scores_t = std::vector<double>;

// diff between to iterations to determine the changed values
using heatmap_diff_t = std::array<std::set<leaked_value_t>, APIC_LEAK_MAX>;

extern signal_t stride_ready;
extern signal_t pressure_done;

extern std::atomic<uint64_t> stride;
extern std::atomic<bool>     do_pressure;
extern std::atomic<bool>     running;

void stop_execution();

// accumulate in the heatmap
void analyze_leak(leak_t const &leaked, heatmap_t &heatmap);

// check if we see a string like `0a-f`
bool is_leak_string(char const *str);

// nice printing
void print_4bytes(char const *s, bool is_diff, bool readable = false);

// print line
void print_line(cache_line_t const &l, bool highlight = false, bool readable = false);
void print_line_paritally(size_t start, size_t end, cache_line_t const &l, bool highlight = false,
                          bool readable = false);

// partially sort each column of the heatmap
scores_t process_heatmap(heatmap_t &heatmap, size_t n_maxima);

// visualize the heatmap including the diff
void print_heatmap(heatmap_t const &heatmap, heatmap_diff_t const &diff, scores_t const &scores, bool readable = false);

// get a diff from the last heatmap
heatmap_diff_t diff_heatmap(heatmap_t const &x, heatmap_t const &y, size_t n_maxima);

// print diffs above a certain threshold
void print_diff(heatmap_t const &heatmap, heatmap_diff_t const &diff, scores_t const &scores, double threshold,
                bool readable = false);

// print sgx page content vie edbgrd
void print_sgx_page(char *page, bool readable = false);
void print_sgx_page_line(char *page, size_t line, bool readable = false);

// get best leaked diff value
leaked_value_t best_diff_value(int col, heatmap_t const &heatmap, heatmap_diff_t const &diff, scores_t const &scores);

// fill line from best diff values
void fill_line(heatmap_t const &heatmap, heatmap_diff_t const &diff, scores_t const &scores, bool lower,
               cache_line_t &result);

// memory pressure thread
void *attacker_memory_pressure(void *punused);

leak_t kernel_leak(uint64_t pid, char *base, size_t offset);

cache_line_t leak_line(uint64_t pid, char *base, uint64_t offset, size_t line);
cache_line_t leak_line_zero(uint64_t pid, char *base, uint64_t offset, size_t line);
