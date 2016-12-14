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
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#ifndef __BITMAP_H
#define __BITMAP_H

typedef unsigned long bitmap_t;
#ifndef CHAR_BIT
#define CHAR_BIT	8
#endif
#define BITMAP_BITS			(sizeof(bitmap_t) * CHAR_BIT)

static inline unsigned long pos_bit(unsigned long pos)
{
	return 1 << ((pos % BITMAP_BITS));
}

static inline unsigned long bit_at(unsigned long pos)
{
	return pos / BITMAP_BITS;
}

static inline void set_bit(bitmap_t *bmp, unsigned long pos)
{
	bmp[bit_at(pos)] |= pos_bit(pos);
}

static inline void clear_bit(bitmap_t *bmp, unsigned long pos)
{
	bmp[bit_at(pos)] &= ~pos_bit(pos);
}

static inline bool test_bit(bitmap_t *bmp, unsigned long pos)
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

static inline void fill_bits(bitmap_t *bmp, unsigned long count)
{
	memset(bmp, 0xFF, count_bits(count));
}

#endif
