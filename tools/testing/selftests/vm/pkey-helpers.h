/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PKEYS_HELPER_H
#define _PKEYS_HELPER_H
#define _GNU_SOURCE
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/mman.h>

/* Define some kernel-like types */
#define  u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif
#define DPRINT_IN_SIGNAL_BUF_SIZE 4096
extern int dprint_in_signal;
extern char dprint_in_signal_buffer[DPRINT_IN_SIGNAL_BUF_SIZE];

#ifdef __GNUC__
__attribute__((format(printf, 1, 2)))
#endif
static inline void sigsafe_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	if (!dprint_in_signal) {
		vprintf(format, ap);
	} else {
		int ret;
		int len = vsnprintf(dprint_in_signal_buffer,
				    DPRINT_IN_SIGNAL_BUF_SIZE,
				    format, ap);
		/*
		 * len is amount that would have been printed,
		 * but actual write is truncated at BUF_SIZE.
		 */
		if (len > DPRINT_IN_SIGNAL_BUF_SIZE)
			len = DPRINT_IN_SIGNAL_BUF_SIZE;
		ret = write(1, dprint_in_signal_buffer, len);
		if (ret < 0)
			abort();
	}
	va_end(ap);
}
#define dprintf_level(level, args...) do {	\
	if (level <= DEBUG_LEVEL)		\
		sigsafe_printf(args);		\
	fflush(NULL);				\
} while (0)
#define dprintf0(args...) dprintf_level(0, args)
#define dprintf1(args...) dprintf_level(1, args)
#define dprintf2(args...) dprintf_level(2, args)
#define dprintf3(args...) dprintf_level(3, args)
#define dprintf4(args...) dprintf_level(4, args)

#if defined(__i386__) || defined(__x86_64__) /* arch */
#include "pkey-x86.h"
#elif __powerpc64__ /* arch */
#include "pkey-powerpc.h"
#else /* arch */
#error Architecture not supported
#endif /* arch */

static inline pkey_reg_t clear_pkey_flags(int pkey, pkey_reg_t flags)
{
	u32 shift = pkey_bit_position(pkey);

	return ~(flags << shift);
}

/*
 * Takes pkey flags and puts them at the right bit position for the given key so
 * that the result can be ORed into the register.
 */
static inline pkey_reg_t left_shift_bits(int pkey, pkey_reg_t flags)
{
	u32 shift = pkey_bit_position(pkey);

	return flags << shift;
}

/*
 * Takes pkey register values and puts the flags for the given pkey at the least
 * significant bits of the returned value.
 */
static inline pkey_reg_t right_shift_bits(int pkey, pkey_reg_t reg)
{
	u32 shift = pkey_bit_position(pkey);

	return reg >> shift;
}

extern pkey_reg_t shadow_pkey_reg;

static inline pkey_reg_t _read_pkey_reg(int line)
{
	pkey_reg_t pkey_reg = __read_pkey_reg();

	dprintf4("read_pkey_reg(line=%d) pkey_reg: "PKEY_REG_FMT
			" shadow: "PKEY_REG_FMT"\n",
			line, pkey_reg, shadow_pkey_reg);
	assert(pkey_reg == shadow_pkey_reg);

	return pkey_reg;
}

#define read_pkey_reg() _read_pkey_reg(__LINE__)

static inline void write_pkey_reg(pkey_reg_t pkey_reg)
{
	dprintf4("%s() changing "PKEY_REG_FMT" to "PKEY_REG_FMT"\n", __func__,
			__read_pkey_reg(), pkey_reg);
	/* will do the shadow check for us: */
	read_pkey_reg();
	__write_pkey_reg(pkey_reg);
	shadow_pkey_reg = pkey_reg;
	dprintf4("%s("PKEY_REG_FMT") pkey_reg: "PKEY_REG_FMT"\n", __func__,
			pkey_reg, __read_pkey_reg());
}

/*
 * These are technically racy. since something could
 * change PKEY register between the read and the write.
 */
static inline void __pkey_access_allow(int pkey, int do_allow)
{
	pkey_reg_t pkey_reg = read_pkey_reg();
	int bit = pkey * 2;

	if (do_allow)
		pkey_reg &= (1<<bit);
	else
		pkey_reg |= (1<<bit);

	dprintf4("pkey_reg now: "PKEY_REG_FMT"\n", read_pkey_reg());
	write_pkey_reg(pkey_reg);
}

static inline void __pkey_write_allow(int pkey, int do_allow_write)
{
	pkey_reg_t pkey_reg = read_pkey_reg();
	int bit = pkey * 2 + 1;

	if (do_allow_write)
		pkey_reg &= (1<<bit);
	else
		pkey_reg |= (1<<bit);

	write_pkey_reg(pkey_reg);
	dprintf4("pkey_reg now: "PKEY_REG_FMT"\n", read_pkey_reg());
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define ALIGN_UP(x, align_to)	(((x) + ((align_to)-1)) & ~((align_to)-1))
#define ALIGN_DOWN(x, align_to) ((x) & ~((align_to)-1))
#define ALIGN_PTR_UP(p, ptr_align_to)	\
		((typeof(p))ALIGN_UP((unsigned long)(p), ptr_align_to))
#define ALIGN_PTR_DOWN(p, ptr_align_to) \
	((typeof(p))ALIGN_DOWN((unsigned long)(p), ptr_align_to))
#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#define PTR_ERR_ENOTSUP ((void *)-ENOTSUP)

int dprint_in_signal;
char dprint_in_signal_buffer[DPRINT_IN_SIGNAL_BUF_SIZE];

extern void abort_hooks(void);
#define pkey_assert(condition) do {		\
	if (!(condition)) {			\
		dprintf0("assert() at %s::%d test_nr: %d iteration: %d\n", \
				__FILE__, __LINE__,	\
				test_nr, iteration_nr);	\
		dprintf0("errno at assert: %d", errno);	\
		abort_hooks();			\
		assert(condition);		\
	}					\
} while (0)
#define raw_assert(cond) assert(cond)

static inline int open_hugepage_file(int flag)
{
	return open(HUGEPAGE_FILE, flag);
}

static inline int get_start_key(void)
{
	return 0;
}

#ifdef si_pkey
static inline u32 *siginfo_get_pkey_ptr(siginfo_t *si)
{
	return &si->si_pkey;
}
#else
static inline u32 *siginfo_get_pkey_ptr(siginfo_t *si)
{
	return (u32 *)(((u8 *)si) + si_pkey_offset);
}
#endif /* si_pkey */

#endif /* _PKEYS_HELPER_H */
