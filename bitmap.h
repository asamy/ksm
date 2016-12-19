/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
 *
 * A simple bitmap to easily manage large bitmaps.  Bitmaps can be
 * 32-bit or 64-bit, 64-bit if on GCC or so, because unsigned long is
 * 64-bit there, however, MSVC treats unsigned long as 32-bit, so each
 * entry can handle up to that and is determined via BITMAP_NBITS.
 *
 * For usage examples, see ksm.c: init_msr_bitmaps() / init_io_bitmaps().
 * Those initialize the MSR/IO bitmaps required for the VMM to run (e.g.
 * nested VMMs, etc.)
 * 
 * Public domain.
*/
#ifndef __BITMAP_H
#define __BITMAP_H

typedef unsigned long bitmap_t;

#ifndef __linux__
#ifndef CHAR_BIT
#define CHAR_BIT	8
#endif
#define BITMAP_BITS			(sizeof(bitmap_t) * CHAR_BIT)

static inline unsigned long pos_bit(unsigned long pos)
{
	return 1 << (pos % BITMAP_BITS);
}

static inline unsigned long bit_at(unsigned long pos)
{
	return pos / BITMAP_BITS;
}

static inline void set_bit(unsigned long pos, bitmap_t *bmp)
{
	bmp[bit_at(pos)] |= pos_bit(pos);
}

static inline void clear_bit(unsigned long pos, bitmap_t *bmp)
{
	bmp[bit_at(pos)] &= ~pos_bit(pos);
}

static inline bool test_bit(unsigned long pos, bitmap_t *bmp)
{
	return !!(bmp[bit_at(pos)] & pos_bit(pos));
}

static inline unsigned long count_bits(unsigned long count)
{
	return ((count + BITMAP_BITS - 1) / BITMAP_BITS) * sizeof(bitmap_t);
}

static inline void clear_bits(bitmap_t *bmp, unsigned long count)
{
	memset(bmp, 0x00, count_bits(count));
}

static inline void fill_bits(bitmap_t *bmp, unsigned long count, unsigned char bits)
{
	memset(bmp, bits, count_bits(count));
}

#endif
#endif

