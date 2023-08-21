/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2023 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef _AMDGPU_WORKLOAD_H_
#define _AMDGPU_WORKLOAD_H_

struct amdgpu_smu_workload {
	struct amdgpu_device	*adev;
	struct mutex		workload_lock;
	struct delayed_work	smu_delayed_work;
	uint32_t		submit_workload_status;
	bool			initialized;
	atomic_t		power_profile_ref[PP_SMC_POWER_PROFILE_COUNT];
};

/* Workload mode names */
static const char * const amdgpu_workload_mode_name[] = {
	"Default",
	"3D",
	"Powersaving",
	"Video",
	"VR",
	"Compute",
	"Custom",
	"Window3D"
};

void amdgpu_workload_profile_put(struct amdgpu_device *adev,
				 uint32_t ring_type);

void amdgpu_workload_profile_set(struct amdgpu_device *adev,
				 uint32_t ring_type);

void amdgpu_workload_profile_suspend(struct amdgpu_device *adev);

void amdgpu_workload_profile_init(struct amdgpu_device *adev);

void amdgpu_workload_profile_fini(struct amdgpu_device *adev);

#endif
