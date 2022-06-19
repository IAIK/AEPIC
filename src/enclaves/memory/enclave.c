#include "enclave_t.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define PALIGN __attribute__((aligned(4096)))

// char data[4096 * 128];
unsigned char PALIGN data[4096];

unsigned char PALIGN text_upper[4096];

unsigned char PALIGN text_lower[] =
    "adapted from the colors of animals by sir john lubbock in a book of natural history (1902, ed. david starr "
    "jordan)the color of animals is by no means a matter of chance; it depends on many considerations, but in the "
    "majority of cases tends to protect the animal from danger by rendering it less conspicuous. perhaps it may be "
    "said that if coloring is mainly protective, there ought to be but few brightly colored animals. there are, "
    "however, not a few cases in which vivid colors are themselves protective. the kingfisher itself, though so "
    "brightly colored, is by no means easy to see. the blue harmonizes with the water, and the bird as it darts along "
    "the stream looks almost like a flash of sunlight.desert animals are generally the color of the desert. thus, for "
    "instance, the lion, the antelope, and the wild donkey are all sand-colored. “indeed,” says canon tristram, “in "
    "the desert, where neither trees, brushwood, nor even undulation of the surface afford the slightest protection to "
    "its foes, a modification of color assimilated to that of the surrounding country is absolutely necessary. hence, "
    "without exception, the upper plumage of every bird, and also the fur of all the smaller mammals and the skin of "
    "all the snakes and lizards, is of one uniform sand color.”the next point is the color of the mature caterpillars, "
    "some of which are brown. this probably makes the caterpillar even more conspicuous among the green leaves than "
    "would otherwise be the case. let us see, then, whether the habits of the insect will throw any light upon the "
    "riddle. what would you do if you were a big caterpillar? why, like most other defenseless creatures, you would "
    "feed by night, and lie concealed by day. so do these caterpillars. when the morning light comes, they creep down "
    "the stem of the food plant, and lie concealed among the thick herbage and dry sticks and leaves, near the ground, "
    "and it is obvious that under such circumstances the brown color really becomes a protection. it might indeed be "
    "argued that the caterpillars, having become brown, concealed themselves on the ground, and that we were reversing "
    "the state of things. but this is not so, because, while we may say as a general rule that large caterpillars feed "
    "by night and lie concealed by day, it is by no means always the case that they are brown; some of them still "
    "retaining the green color. we may then conclude that the habit of concealing themselves by day came first, and "
    "that the brown color is a later adaptation.";

int printf(const char *fmt, ...) {
    char    buf[5000] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return 0;
}

int puts(const char *buf) {
    char buffer[1000];
    snprintf(buffer, sizeof(buffer), "%s\n", buf);
    ocall_print_string(buffer);
    return 0;
}

static void __attribute__((aligned(4096), naked)) victim_function() {
    asm volatile(R"(
        ret
    .align 4096
        nop
    )");
}

void ecall_init() {
    printf("enclave init!\n");

    for ( size_t cl = 0; cl < 4096 / 64; ++cl ) {
        for ( size_t bb = 0; bb < 64 / 4; ++bb ) {
            char buffer[10];
            snprintf(buffer, sizeof(buffer), "%02lx-%lx", cl, bb);
            unsigned int *p = (unsigned int *)buffer;
            //*p |= 0x80808080; // mark it
            memcpy(data + cl * 64 + bb * 4, buffer, 4);
        }
    }

    for ( size_t i = 0; i < 4096; ++i ) {
        text_upper[i] = text_lower[i] & ~0x20;
    }
}
