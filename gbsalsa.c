#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define rol(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* Cookie Run-specific constants. */
const uint8_t key[] =
{
	0xF7, 0x9B, 0xF7, 0x33, 0xF2, 0x3F, 0x9D, 0x7A,
	0xF2, 0xA2, 0x91, 0xCB, 0x4D, 0xCB, 0x5E, 0x49,
	0x63, 0xE6, 0xA8, 0x71, 0xE0, 0x51, 0x2C, 0xE1,
	0x46, 0xBD, 0x03, 0x67, 0x93, 0x56, 0xA4, 0x73
};

const uint8_t iv[] =
{
	0xBC, 0x79, 0xCC, 0x75, 0x91, 0xB4, 0x8D, 0x70
};

/* Salsa20-specific constants. */
const uint8_t state[4][4] =
{
	{ 'e', 'x', 'p', 'a' },
	{ 'n', 'd', ' ', '3' },
	{ '2', '-', 'b', 'y' },
	{ 't', 'e', ' ', 'k' }
};

/* Implements the Salsa20 cipher. */
void crypt(uint8_t *buf, uint32_t len)
{
	uint8_t  exp[64];
	uint8_t  n[16] = { 0 };
	uint32_t i, j, k;
	uint32_t x[16];

	for (i = 0; i < 8; ++i)
		n[i] = iv[i];

	for (i = 0; i < len; i++)
	{
		if (i % 64 == 0)
		{
			*(uint32_t *)(n + 8) = i / 64;

			for (j = 0; j < 64; j += 20)
				for (k = 0; k < 4; k++)
					exp[j + k] = state[j / 20][k];

			for (j = 0; j < 16; j++)
			{
				exp[4  + j] = key[j];
				exp[44 + j] = key[j + 16];
				exp[24 + j] = n[j];
			}
			 
			for (j = 0; j < 16; j++)
				x[j] = ((uint32_t *)exp)[j];
	
			for (j = 0; j < 10; j++)
			{
				x[ 4] ^= rol(x[ 0] + x[12],  7);
				x[ 8] ^= rol(x[ 4] + x[ 0],  9);
				x[12] ^= rol(x[ 8] + x[ 4], 13);
				x[ 0] ^= rol(x[12] + x[ 8], 18);
				x[ 9] ^= rol(x[ 5] + x[ 1],  7);
				x[13] ^= rol(x[ 9] + x[ 5],  9);
				x[ 1] ^= rol(x[13] + x[ 9], 13);
				x[ 5] ^= rol(x[ 1] + x[13], 18);
				x[14] ^= rol(x[10] + x[ 6],  7);
				x[ 2] ^= rol(x[14] + x[10],  9);
				x[ 6] ^= rol(x[ 2] + x[14], 13);
				x[10] ^= rol(x[ 6] + x[ 2], 18);
				x[ 3] ^= rol(x[15] + x[11],  7);
				x[ 7] ^= rol(x[ 3] + x[15],  9);
				x[11] ^= rol(x[ 7] + x[ 3], 13);
				x[15] ^= rol(x[11] + x[ 7], 18);
				x[ 1] ^= rol(x[ 0] + x[ 3],  7);
				x[ 2] ^= rol(x[ 1] + x[ 0],  9);
				x[ 3] ^= rol(x[ 2] + x[ 1], 13);
				x[ 0] ^= rol(x[ 3] + x[ 2], 18);
				x[ 6] ^= rol(x[ 5] + x[ 4],  7);
				x[ 7] ^= rol(x[ 6] + x[ 5],  9);
				x[ 4] ^= rol(x[ 7] + x[ 6], 13);
				x[ 5] ^= rol(x[ 4] + x[ 7], 18);
				x[11] ^= rol(x[10] + x[ 9],  7);
				x[ 8] ^= rol(x[11] + x[10],  9);
				x[ 9] ^= rol(x[ 8] + x[11], 13);
				x[10] ^= rol(x[ 9] + x[ 8], 18);
				x[12] ^= rol(x[15] + x[14],  7);
				x[13] ^= rol(x[12] + x[15],  9);
				x[14] ^= rol(x[13] + x[12], 13);
				x[15] ^= rol(x[14] + x[13], 18);
			}
	
			for (j = 0; j < 16; j++)
				((uint32_t *)exp)[j] += x[j];
		}

		buf[i] ^= exp[i % 64];
	}
}


int main(int argc, char **argv)
{
	FILE *f;
	uint32_t len;
	char *buf;
	
	if (argc != 2)
	{
		printf("Usage: %s file.mid\n", argv[0]);
		return 0;
	}
		
	if ((f = fopen(argv[1], "rb+")) == NULL)
	{
		perror("Error");
		return 1;
	}
	
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	rewind(f);
	
	buf = malloc(len);
	fread(buf, 1, len, f);
	
	crypt(buf, len);
	
	rewind(f);
	fwrite(buf, 1, len, f);
	fclose(f);
	
	free(buf);
	
	return 0;
	
}
