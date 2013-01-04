// Copyright (c) 2012 dndx (idndx.com)

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <string.h>
#include "md5.h"
#include "encrypt.h"

#ifdef HIGHFIRST
	uint64_t swap_uint64( uint64_t val )
	{
	    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
	    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
	    return (val << 32) | (val >> 32);
	}
#endif /* BIG ENDIAN */

/*
 * message must be uint8_t[16]
 */
void md5(const uint8_t *text, uint8_t *message)
{
	struct MD5Context context;
	MD5Init(&context);
	MD5Update(&context, text, strlen((const char*)text));
	MD5Final(message, &context);
}

static void merge(uint8_t *arr, int start, int end, int mid, int ei, uint64_t keynum)
{
	int asize = mid - start + 1;
	uint8_t a[asize];
	memcpy(a, arr + start, asize);
	uint8_t *b = arr;
	uint8_t *result = arr;

	int i = 0;
	int j = mid + 1;
	int imax = asize;
	int jmax = end + 1;
	int k = start;

	while (i < imax && j < jmax) {
		if (keynum % (a[i] + ei) <= keynum % (b[j] + ei)) {
			result[k] = a[i];
			i++;
			k++;
		} else {
			result[k] = b[j];
			j++;
			k++;
		}
	}

	while (i < imax) {
		result[k] = a[i];
		i++;
		k++;
	}
	while (j < jmax) {
		result[k] = b[j];
		j++;
		k++;
	}
}

static void merge_sort(uint8_t *arr, int start, int end, int ei, uint64_t keynum)
{
	if (end - start <= 0) {
		return;
	}

	int mid = (start + end) / 2;

	merge_sort(arr, start, mid, ei, keynum);
	merge_sort(arr, mid + 1, end, ei, keynum);
	merge(arr, start, end, mid, ei, keynum);
}

static void mergesort(uint8_t *arr, int length, int ei, uint64_t keynum)
{
	merge_sort(arr, 0, length - 1, ei, keynum);
}

/*
 * encrypt_table and decrypt_table must be uint8_t[TABLE_SIZE]
 */
void make_tables(const uint8_t *key, uint8_t *encrypt_table, uint8_t *decrypt_table)
{
	uint8_t digest[16];
	int ei;
	uint64_t keynum;

	md5(key, digest);
	memcpy(&keynum, digest, 8);
	#ifdef HIGHFIRST
	 	keynum = swap_uint64(keynum);
	#endif /* BIG ENDIAN */
	uint8_t temp_table[TABLE_SIZE];
	for (ei=0; ei<TABLE_SIZE; ei++) {
		temp_table[ei] = ei;
	}
	for (ei=1; ei<1024; ei++) {
		mergesort(temp_table, TABLE_SIZE, ei, keynum);
	}
	memcpy(encrypt_table, temp_table, TABLE_SIZE);
	for (ei=0; ei<TABLE_SIZE; ei++) {
		decrypt_table[encrypt_table[ei]] = ei;
	}
}

void shadow_encrypt(uint8_t *data, uint8_t *encrypt_table, register unsigned int length)
{
	while (length--) {
		data[length] = encrypt_table[data[length]];
	}
}

void shadow_decrypt(uint8_t *data, uint8_t *decrypt_table, register unsigned int length)
{
	while (length--) {
		data[length] = decrypt_table[data[length]];
	}
}
