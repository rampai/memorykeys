/*
 * Ptrace test for Memory Protection Key registers
 *
 * Copyright (C) 2015 Anshuman Khandual, IBM Corporation.
 * Copyright (C) 2017 IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <semaphore.h>
#include "ptrace.h"

#ifndef __NR_pkey_alloc
#define __NR_pkey_alloc		384
#endif

#ifndef __NR_pkey_free
#define __NR_pkey_free		385
#endif

#ifndef NT_PPC_PKEY
#define NT_PPC_PKEY		0x110
#endif

#ifndef PKEY_DISABLE_EXECUTE
#define PKEY_DISABLE_EXECUTE	0x4
#endif

#define AMR_BITS_PER_PKEY 2
#define PKEY_REG_BITS (sizeof(u64) * 8)
#define pkeyshift(pkey) (PKEY_REG_BITS - ((pkey + 1) * AMR_BITS_PER_PKEY))

static const char user_read[] = "[User Read (Running)]";
static const char user_write[] = "[User Write (Running)]";
static const char ptrace_read_running[] = "[Ptrace Read (Running)]";
static const char ptrace_write_running[] = "[Ptrace Write (Running)]";

/* Information shared between the parent and the child. */
struct shared_info {
	/* AMR value the parent expects to read from the child. */
	unsigned long amr1;

	/* AMR value the parent is expected to write to the child. */
	unsigned long amr2;

	/* AMR value that ptrace should refuse to write to the child. */
	unsigned long amr3;

	/* IAMR value the parent expects to read from the child. */
	unsigned long expected_iamr;

	/* UAMOR value the parent expects to read from the child. */
	unsigned long expected_uamor;

	/*
	 * IAMR and UAMOR values that ptrace should refuse to write to the child
	 * (even though they're valid ones) because userspace doesn't have
	 * access to those registers.
	 */
	unsigned long new_iamr;
	unsigned long new_uamor;

	/* The parent waits on this semaphore. */
	sem_t sem_parent;

	/* If true, the child should give up as well. */
	bool parent_gave_up;

	/* The child waits on this semaphore. */
	sem_t sem_child;

	/* If true, the parent should give up as well. */
	bool child_gave_up;
};

#define CHILD_FAIL_IF(x, info)						\
	do {								\
		if ((x)) {						\
			fprintf(stderr,					\
				"[FAIL] Test FAILED on line %d\n", __LINE__); \
			(info)->child_gave_up = true;			\
			prod_parent(info);				\
			return 1;					\
		}							\
	} while (0)

#define PARENT_FAIL_IF(x, info)						\
	do {								\
		if ((x)) {						\
			fprintf(stderr,					\
				"[FAIL] Test FAILED on line %d\n", __LINE__); \
			(info)->parent_gave_up = true;			\
			prod_child(info);				\
			return 1;					\
		}							\
	} while (0)

static int wait_child(struct shared_info *info)
{
	int ret;

	/* Wait until the child prods us. */
	ret = sem_wait(&info->sem_parent);
	if (ret) {
		perror("Error waiting for child");
		return TEST_FAIL;
	}

	return info->child_gave_up ? TEST_FAIL : TEST_PASS;
}

static int prod_child(struct shared_info *info)
{
	int ret;

	/* Unblock the child now. */
	ret = sem_post(&info->sem_child);
	if (ret) {
		perror("Error prodding child");
		return TEST_FAIL;
	}

	return TEST_PASS;
}

static int wait_parent(struct shared_info *info)
{
	int ret;

	/* Wait until the parent prods us. */
	ret = sem_wait(&info->sem_child);
	if (ret) {
		perror("Error waiting for parent");
		return TEST_FAIL;
	}

	return info->parent_gave_up ? TEST_FAIL : TEST_PASS;
}

static int prod_parent(struct shared_info *info)
{
	int ret;

	/* Unblock the parent now. */
	ret = sem_post(&info->sem_parent);
	if (ret) {
		perror("Error prodding parent");
		return TEST_FAIL;
	}

	return TEST_PASS;
}

static int sys_pkey_alloc(unsigned long flags, unsigned long init_access_rights)
{
	return syscall(__NR_pkey_alloc, flags, init_access_rights);
}

static int sys_pkey_free(int pkey)
{
	return syscall(__NR_pkey_free, pkey);
}

static int ptrace_read_regs(pid_t child, unsigned long regs[], int n)
{
	struct iovec iov;
	long ret;

	FAIL_IF(start_trace(child));

	iov.iov_base = regs;
	iov.iov_len = n * sizeof(unsigned long);

	ret = ptrace(PTRACE_GETREGSET, child, NT_PPC_PKEY, &iov);
	FAIL_IF(ret != 0);

	FAIL_IF(stop_trace(child));

	return TEST_PASS;
}

static long ptrace_write_regs(pid_t child, unsigned long regs[], int n)
{
	struct iovec iov;
	long ret;

	FAIL_IF(start_trace(child));

	iov.iov_base = regs;
	iov.iov_len = n * sizeof(unsigned long);

	ret = ptrace(PTRACE_SETREGSET, child, NT_PPC_PKEY, &iov);

	FAIL_IF(stop_trace(child));

	return ret;
}

static int child(struct shared_info *info)
{
	unsigned long reg;
	bool disable_execute = true;
	int pkey1, pkey2, pkey3;
	int ret;

	/* Get some pkeys so that we can change their bits in the AMR. */
	pkey1 = sys_pkey_alloc(0, PKEY_DISABLE_EXECUTE);
	if (pkey1 < 0) {
		pkey1 = sys_pkey_alloc(0, 0);
		CHILD_FAIL_IF(pkey1 < 0, info);

		disable_execute = false;
	}

	pkey2 = sys_pkey_alloc(0, 0);
	CHILD_FAIL_IF(pkey2 < 0, info);

	pkey3 = sys_pkey_alloc(0, 0);
	CHILD_FAIL_IF(pkey3 < 0, info);

	info->amr1 = 3ul << pkeyshift(pkey1);
	info->amr2 = 3ul << pkeyshift(pkey2);
	info->amr3 = info->amr2 | 3ul << pkeyshift(pkey3);

	if (disable_execute)
		info->expected_iamr = 1ul << pkeyshift(pkey1);
	else
		info->expected_iamr = 0;

	info->expected_uamor = 3ul << pkeyshift(pkey1) |
				3ul << pkeyshift(pkey2);
	info->new_iamr = 1ul << pkeyshift(pkey1) | 1ul << pkeyshift(pkey2);
	info->new_uamor = 3ul << pkeyshift(pkey1);

	/*
	 * We won't use pkey3. We just want a plausible but invalid key to test
	 * whether ptrace will let us write to AMR bits we are not supposed to.
	 *
	 * This also tests whether the kernel restores the UAMOR permissions
	 * after a key is freed.
	 */
	sys_pkey_free(pkey3);

	printf("%-30s AMR: %016lx pkey1: %d pkey2: %d pkey3: %d\n",
	       user_write, info->amr1, pkey1, pkey2, pkey3);

	mtspr(SPRN_AMR, info->amr1);

	/* Wait for parent to read our AMR value and write a new one. */
	ret = prod_parent(info);
	CHILD_FAIL_IF(ret, info);

	ret = wait_parent(info);
	if (ret)
		return ret;

	reg = mfspr(SPRN_AMR);

	printf("%-30s AMR: %016lx\n", user_read, reg);

	CHILD_FAIL_IF(reg != info->amr2, info);

	/*
	 * Wait for parent to try to write an invalid AMR value.
	 */
	ret = prod_parent(info);
	CHILD_FAIL_IF(ret, info);

	ret = wait_parent(info);
	if (ret)
		return ret;

	reg = mfspr(SPRN_AMR);

	printf("%-30s AMR: %016lx\n", user_read, reg);

	CHILD_FAIL_IF(reg != info->amr2, info);

	/*
	 * Wait for parent to try to write an IAMR and a UAMOR value. We can't
	 * verify them, but we can verify that the AMR didn't change.
	 */
	ret = prod_parent(info);
	CHILD_FAIL_IF(ret, info);

	ret = wait_parent(info);
	if (ret)
		return ret;

	reg = mfspr(SPRN_AMR);

	printf("%-30s AMR: %016lx\n", user_read, reg);

	CHILD_FAIL_IF(reg != info->amr2, info);

	/* Now let parent now that we are finished. */

	ret = prod_parent(info);
	CHILD_FAIL_IF(ret, info);

	return TEST_PASS;
}

static int parent(struct shared_info *info, pid_t pid)
{
	unsigned long regs[4];
	int ret, status;

	ret = wait_child(info);
	if (ret)
		return ret;

	/* Verify that we can read the pkey registers from the child. */
	ret = ptrace_read_regs(pid, regs, 3);
	PARENT_FAIL_IF(ret, info);

	printf("%-30s AMR: %016lx IAMR: %016lx UAMOR: %016lx\n",
	       ptrace_read_running, regs[0], regs[1], regs[2]);

	PARENT_FAIL_IF(regs[0] != info->amr1, info);
	PARENT_FAIL_IF(regs[1] != info->expected_iamr, info);
	PARENT_FAIL_IF(regs[2] != info->expected_uamor, info);

	/* Write valid AMR value in child. */
	ret = ptrace_write_regs(pid, &info->amr2, 1);
	PARENT_FAIL_IF(ret, info);

	printf("%-30s AMR: %016lx\n", ptrace_write_running, info->amr2);

	/* Wake up child so that it can verify it changed. */
	ret = prod_child(info);
	PARENT_FAIL_IF(ret, info);

	ret = wait_child(info);
	if (ret)
		return ret;

	/* Write invalid AMR value in child. */
	ret = ptrace_write_regs(pid, &info->amr3, 1);
	PARENT_FAIL_IF(ret, info);

	printf("%-30s AMR: %016lx\n", ptrace_write_running, info->amr3);

	/* Wake up child so that it can verify it didn't change. */
	ret = prod_child(info);
	PARENT_FAIL_IF(ret, info);

	ret = wait_child(info);
	if (ret)
		return ret;

	/* Try to write to IAMR. */
	regs[0] = info->amr1;
	regs[1] = info->new_iamr;
	ret = ptrace_write_regs(pid, regs, 2);
	PARENT_FAIL_IF(!ret, info);

	printf("%-30s AMR: %016lx IAMR: %016lx\n",
	       ptrace_write_running, regs[0], regs[1]);

	/* Try to write to IAMR and UAMOR. */
	regs[2] = info->new_uamor;
	ret = ptrace_write_regs(pid, regs, 3);
	PARENT_FAIL_IF(!ret, info);

	printf("%-30s AMR: %016lx IAMR: %016lx UAMOR: %016lx\n",
	       ptrace_write_running, regs[0], regs[1], regs[2]);

	/* Verify that all registers still have their expected values. */
	ret = ptrace_read_regs(pid, regs, 3);
	PARENT_FAIL_IF(ret, info);

	printf("%-30s AMR: %016lx IAMR: %016lx UAMOR: %016lx\n",
	       ptrace_read_running, regs[0], regs[1], regs[2]);

	PARENT_FAIL_IF(regs[0] != info->amr2, info);
	PARENT_FAIL_IF(regs[1] != info->expected_iamr, info);
	PARENT_FAIL_IF(regs[2] != info->expected_uamor, info);

	/* Wake up child so that it can verify AMR didn't change and wrap up. */
	ret = prod_child(info);
	PARENT_FAIL_IF(ret, info);

	ret = wait(&status);
	if (ret != pid) {
		printf("Child's exit status not captured\n");
		ret = TEST_PASS;
	} else if (!WIFEXITED(status)) {
		printf("Child exited abnormally\n");
		ret = TEST_FAIL;
	} else
		ret = WEXITSTATUS(status) ? TEST_FAIL : TEST_PASS;

	return ret;
}

static int ptrace_pkey(void)
{
	struct shared_info *info;
	int shm_id;
	int ret;
	pid_t pid;

	shm_id = shmget(IPC_PRIVATE, sizeof(*info), 0777 | IPC_CREAT);
	info = shmat(shm_id, NULL, 0);

	ret = sem_init(&info->sem_parent, 1, 0);
	if (ret) {
		perror("Semaphore initialization failed");
		return TEST_FAIL;
	}
	ret = sem_init(&info->sem_child, 1, 0);
	if (ret) {
		perror("Semaphore initialization failed");
		return TEST_FAIL;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork() failed");
		ret = TEST_FAIL;
	} else if (pid == 0)
		ret = child(info);
	else
		ret = parent(info, pid);

	shmdt(info);

	if (pid) {
		sem_destroy(&info->sem_parent);
		sem_destroy(&info->sem_child);
		shmctl(shm_id, IPC_RMID, NULL);
	}

	return ret;
}

int main(int argc, char *argv[])
{
	return test_harness(ptrace_pkey, "ptrace_pkey");
}
