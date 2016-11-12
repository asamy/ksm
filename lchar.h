#ifndef __LCHAR_H
#define __LCHAR_H

/* Don't look at this file  */
/* This still needs some fixes...  */

#define LCHAR_A		a
#define LCHAR_B		b
#define LCHAR_C		c
#define LCHAR_D		d
#define LCHAR_E		e
#define LCHAR_F		f
#define LCHAR_J		j
#define LCHAR_I		i
#define LCHAR_K		k
#define LCHAR_L		l
#define LCHAR_M		m
#define LCHAR_N		n
#define LCHAR_O		o
#define LCHAR_P		p
#define LCHAR_Q		q
#define LCHAR_R		r
#define LCHAR_S		s
#define LCHAR_T		t
#define LCHAR_U		u
#define LCHAR_V		v
#define LCHAR_W		w
#define LCHAR_X		x
#define LCHAR_Y		y
#define LCHAR_Z		z

/* upcase to locase  */
#define CONCAT(a, b)	a ## b
#define CONCAT2(x, i)	CONCAT(CONCAT(LCHAR_, x[i]), CONCAT(LCHAR_, x[i+1]))
#define CONCAT4(x, i)	CONCAT(CONCAT2(x, i), CONCAT2(x, i+2))
#define CONCAT8(x, i)	CONCAT(CONCAT4(x, i), CONCAT4(x, i+4))
#define CONCAT16(x, i)	CONCAT(CONCAT8(x, i), CONCAT8(x, i+8))
#define LOCASE(x)	CONCAT((##x)[0], (##x)[1])

#endif
