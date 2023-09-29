// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Google LLC.
 *
 * Tests for the K7_HWCR MSR.
 */

#define _GNU_SOURCE /* for program_invocation_short_name */
#include <sys/ioctl.h>

#include "test_util.h"
#include "kvm_util.h"
#include "vmx.h"

void test_hwcr_bit(struct kvm_vcpu *vcpu, unsigned int bit)
{
	const unsigned long long ignored = BIT_ULL(3) | BIT_ULL(6) | BIT_ULL(8);
	const unsigned long long valid = BIT_ULL(18) | BIT_ULL(24);
	const unsigned long long legal = ignored | valid;
	uint64_t val = BIT_ULL(bit);
	uint64_t check;
	int r;

	r = _vcpu_set_msr(vcpu, MSR_K7_HWCR, val);
	TEST_ASSERT((r == 1 && (val & legal)) || (r == 0 && !(val & legal)),
		    "Unexpected result (%d) when setting HWCR[bit %u]", r, bit);
	check =	vcpu_get_msr(vcpu, MSR_K7_HWCR);
	if (val & valid) {
		TEST_ASSERT(check == val,
			    "Bit %u: unexpected HWCR %lx; expected %lx", bit,
			    check, val);
		vcpu_set_msr(vcpu, MSR_K7_HWCR, 0);
	} else {
		TEST_ASSERT(!check,
			    "Bit %u: unexpected HWCR %lx; expected 0", bit,
			    check);
	}
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	unsigned int bit;

	vm = vm_create_with_one_vcpu(&vcpu, NULL);

	for (bit = 0; bit < BITS_PER_LONG; bit++)
		test_hwcr_bit(vcpu, bit);

	kvm_vm_free(vm);
}
