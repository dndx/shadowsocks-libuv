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

static int ei;
static uint64_t keynum;

#ifdef HIGHFIRST
	uint64_t swap_uint64( uint64_t val )
	{
	    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
	    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
	    return (val << 32) | (val >> 32);
	}
#endif /* BIG ENDIAN */

/*
 * message must be unsigned char[16]
 */
void md5(const unsigned char *text, unsigned char *message)
{
	struct MD5Context context;
	MD5Init(&context);
	MD5Update(&context, text, strlen((const char*)text));
	MD5Final(message, &context);
}

static void merge(unsigned char *arr, int start, int end, int mid)
{
	int asize = mid - start + 1;
	unsigned char a[asize];
	memcpy(a, arr + start, asize);
	unsigned char *b = arr;
	unsigned char *result = arr;

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

static void merge_sort(unsigned char *arr, int start, int end)
{
	if (end - start <= 0) {
		return;
	}

	int mid = (start + end) / 2;

	merge_sort(arr, start, mid);
    merge_sort(arr, mid + 1, end);
    merge(arr, start, end, mid);
}

static void mergesort(unsigned char *arr, int length)
{
	merge_sort(arr, 0, length - 1);
}

/*
 * encrypt_table and decrypt_table must be unsigned char[TABLE_SIZE]
 */
void make_tables(const unsigned char *key, unsigned char *encrypt_table, unsigned char *decrypt_table)
{
	unsigned char digest[16];
	md5(key, digest);
	memcpy(&keynum, digest, 8);
	#ifdef HIGHFIRST
	 	keynum = swap_uint64(keynum);
	#endif /* BIG ENDIAN */
	unsigned char temp_table[TABLE_SIZE];
	for (ei=0; ei<TABLE_SIZE; ei++) {
		temp_table[ei] = ei;
	}
	for (ei=1; ei<1024; ei++) {
		mergesort(temp_table, TABLE_SIZE);
	}
	memcpy(encrypt_table, temp_table, TABLE_SIZE);
	for (ei=0; ei<TABLE_SIZE; ei++) {
		decrypt_table[encrypt_table[ei]] = ei;
	}
}

void shadow_encrypt(unsigned char *data, unsigned char *encrypt_table, register unsigned int length)
{
	while (length--) {
		data[length] = encrypt_table[data[length]];
	}
}

void shadow_decrypt(unsigned char *data, unsigned char *decrypt_table, register unsigned int length)
{
	while (length--) {
		data[length] = decrypt_table[data[length]];
	}
}
