/*
 * Copyright 2021 Advanced Micro Devices, Inc.
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

#include <drm/amdgpu_drm.h>
#include "amdgpu.h"

/**
 * amdgpu_profile_ioctl - Manages settings for profiling.
 *
 * @dev: drm device pointer
 * @data: drm_amdgpu_vm
 * @filp: drm file pointer
 *
 * Returns:
 * 0 for success, -errno for errors.
 */
int amdgpu_profile_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *filp)
{
	union drm_amdgpu_profile *args = data;
	struct amdgpu_device *adev = drm_to_adev(dev);
	const struct amd_pm_funcs *pp_funcs = adev->powerplay.pp_funcs;
	enum amd_dpm_forced_level current_level, requested_level;
	int r;

	if (pp_funcs->get_performance_level)
		current_level = amdgpu_dpm_get_performance_level(adev);
	else
		current_level = adev->pm.dpm.forced_level;

	switch (args->in.op) {
	case AMDGPU_PROFILE_OP_GET_STABLE_PSTATE:
		if (args->in.flags)
			return -EINVAL;
		switch (current_level) {
		case AMD_DPM_FORCED_LEVEL_PROFILE_STANDARD:
			args->out.flags = AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_STANDARD;
			break;
		case AMD_DPM_FORCED_LEVEL_PROFILE_MIN_SCLK:
			args->out.flags = AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_MIN_SCLK;
			break;
		case AMD_DPM_FORCED_LEVEL_PROFILE_MIN_MCLK:
			args->out.flags = AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_MIN_MCLK;
			break;
		case AMD_DPM_FORCED_LEVEL_PROFILE_PEAK:
			args->out.flags = AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_PEAK;
			break;
		default:
			args->out.flags = AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_NONE;
			break;
		}
		break;
	case AMDGPU_PROFILE_OP_SET_STABLE_PSTATE:
		if (args->in.flags & ~AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_MASK)
			return -EINVAL;
		switch (args->in.flags & AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_MASK) {
		case AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_STANDARD:
			requested_level = AMD_DPM_FORCED_LEVEL_PROFILE_STANDARD;
			break;
		case AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_MIN_SCLK:
			requested_level = AMD_DPM_FORCED_LEVEL_PROFILE_MIN_SCLK;
			break;
		case AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_MIN_MCLK:
			requested_level = AMD_DPM_FORCED_LEVEL_PROFILE_MIN_MCLK;
			break;
		case AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_PEAK:
			requested_level = AMD_DPM_FORCED_LEVEL_PROFILE_PEAK;
			break;
		case AMDGPU_PROFILE_FLAGS_STABLE_PSTATE_NONE:
			requested_level = AMD_DPM_FORCED_LEVEL_AUTO;
			break;
		default:
			return -EINVAL;
		}

		if ((current_level != requested_level) && pp_funcs->force_performance_level) {
			mutex_lock(&adev->pm.mutex);
			r = amdgpu_dpm_force_performance_level(adev, requested_level);
			if (!r)
				adev->pm.dpm.forced_level = requested_level;
			mutex_unlock(&adev->pm.mutex);
			if (r)
				return r;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

