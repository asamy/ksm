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
