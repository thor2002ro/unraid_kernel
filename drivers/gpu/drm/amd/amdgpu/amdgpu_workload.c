// SPDX-License-Identifier: MIT
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

#include "amdgpu.h"

/* 100 millsecond timeout */
#define SMU_IDLE_TIMEOUT	msecs_to_jiffies(100)

static enum PP_SMC_POWER_PROFILE
ring_to_power_profile(uint32_t ring_type)
{
	switch (ring_type) {
	case AMDGPU_RING_TYPE_GFX:
		return PP_SMC_POWER_PROFILE_FULLSCREEN3D;
	case AMDGPU_RING_TYPE_COMPUTE:
		return PP_SMC_POWER_PROFILE_COMPUTE;
	case AMDGPU_RING_TYPE_UVD:
	case AMDGPU_RING_TYPE_VCE:
	case AMDGPU_RING_TYPE_UVD_ENC:
	case AMDGPU_RING_TYPE_VCN_DEC:
	case AMDGPU_RING_TYPE_VCN_ENC:
	case AMDGPU_RING_TYPE_VCN_JPEG:
		return PP_SMC_POWER_PROFILE_VIDEO;
	default:
		return PP_SMC_POWER_PROFILE_BOOTUP_DEFAULT;
	}
}

static int
amdgpu_power_profile_set(struct amdgpu_device *adev,
			 enum PP_SMC_POWER_PROFILE profile)
{
	int ret = amdgpu_dpm_switch_power_profile(adev, profile, true);

	if (!ret) {
		/* Set the bit for the submitted workload profile */
		adev->smu_workload.submit_workload_status |= (1 << profile);
		atomic_inc(&adev->smu_workload.power_profile_ref[profile]);
	}

	return ret;
}

static int
amdgpu_power_profile_clear(struct amdgpu_device *adev,
			   enum PP_SMC_POWER_PROFILE profile)
{
	int ret = amdgpu_dpm_switch_power_profile(adev, profile, false);

	if (!ret) {
		/* Clear the bit for the submitted workload profile */
		adev->smu_workload.submit_workload_status &= ~(1 << profile);
	}

	return ret;
}

static void
amdgpu_power_profile_idle_work_handler(struct work_struct *work)
{

	struct amdgpu_smu_workload *workload = container_of(work,
						      struct amdgpu_smu_workload,
						      smu_delayed_work.work);
	struct amdgpu_device *adev = workload->adev;
	bool reschedule = false;
	int index  = fls(workload->submit_workload_status);
	int ret;

	mutex_lock(&workload->workload_lock);
	for (; index > 0; index--) {
		int val = atomic_read(&workload->power_profile_ref[index]);

		if (val) {
			reschedule = true;
		} else {
			if (workload->submit_workload_status &
			    (1 << index)) {
				ret = amdgpu_power_profile_clear(adev, index);
				if (ret) {
					DRM_WARN("Failed to clear workload %s,error = %d\n",
						 amdgpu_workload_mode_name[index], ret);
					goto exit;
				}
			}
		}
	}
	if (reschedule)
		schedule_delayed_work(&workload->smu_delayed_work,
				      SMU_IDLE_TIMEOUT);
exit:
	mutex_unlock(&workload->workload_lock);
}

void amdgpu_workload_profile_put(struct amdgpu_device *adev,
				 uint32_t ring_type)
{
	struct amdgpu_smu_workload *workload = &adev->smu_workload;
	enum PP_SMC_POWER_PROFILE profile = ring_to_power_profile(ring_type);

	if (profile == PP_SMC_POWER_PROFILE_BOOTUP_DEFAULT)
		return;

	mutex_lock(&workload->workload_lock);

	if (!atomic_read(&workload->power_profile_ref[profile])) {
		DRM_WARN("Power profile %s ref. count error\n",
			 amdgpu_workload_mode_name[profile]);
	} else {
		atomic_dec(&workload->power_profile_ref[profile]);
		schedule_delayed_work(&workload->smu_delayed_work,
				      SMU_IDLE_TIMEOUT);
	}

	mutex_unlock(&workload->workload_lock);
}

void amdgpu_workload_profile_set(struct amdgpu_device *adev,
				 uint32_t ring_type)
{
	struct amdgpu_smu_workload *workload = &adev->smu_workload;
	enum PP_SMC_POWER_PROFILE profile = ring_to_power_profile(ring_type);
	int ret;

	if (profile == PP_SMC_POWER_PROFILE_BOOTUP_DEFAULT)
		return;

	mutex_lock(&workload->workload_lock);
	cancel_delayed_work_sync(&workload->smu_delayed_work);

	ret = amdgpu_power_profile_set(adev, profile);
	if (ret) {
		DRM_WARN("Failed to set workload profile to %s, error = %d\n",
			 amdgpu_workload_mode_name[profile], ret);
		goto exit;
	}

	/* Clear the already finished jobs of higher power profile*/
	for (int index = fls(workload->submit_workload_status);
	     index > profile; index--) {
		if (!atomic_read(&workload->power_profile_ref[index]) &&
		    workload->submit_workload_status & (1 << index)) {
			ret = amdgpu_power_profile_clear(adev, index);
			if (ret) {
				DRM_WARN("Failed to clear workload %s, err = %d\n",
					 amdgpu_workload_mode_name[profile], ret);
				goto exit;
			}
		}
	}

exit:
	mutex_unlock(&workload->workload_lock);
}

void amdgpu_workload_profile_suspend(struct amdgpu_device *adev)
{
	struct amdgpu_smu_workload *workload = &adev->smu_workload;
	int ret;

	mutex_lock(&workload->workload_lock);
	cancel_delayed_work_sync(&workload->smu_delayed_work);

	/* Clear all the set GPU power profile*/
	for (int index = fls(workload->submit_workload_status);
	     index > 0; index--) {
		if (workload->submit_workload_status & (1 << index)) {
			atomic_set(&workload->power_profile_ref[index], 0);
			ret = amdgpu_power_profile_clear(adev, index);
			if (ret)
				DRM_WARN("Failed to clear power profile %s, err = %d\n",
					 amdgpu_workload_mode_name[index], ret);
		}
	}
	workload->submit_workload_status = 0;
	mutex_unlock(&workload->workload_lock);
}

void amdgpu_workload_profile_init(struct amdgpu_device *adev)
{
	adev->smu_workload.adev = adev;
	adev->smu_workload.submit_workload_status = 0;
	adev->smu_workload.initialized = true;

	mutex_init(&adev->smu_workload.workload_lock);
	INIT_DELAYED_WORK(&adev->smu_workload.smu_delayed_work,
			  amdgpu_power_profile_idle_work_handler);
}

void amdgpu_workload_profile_fini(struct amdgpu_device *adev)
{
	if (!adev->smu_workload.initialized)
		return;

	cancel_delayed_work_sync(&adev->smu_workload.smu_delayed_work);
	adev->smu_workload.submit_workload_status = 0;
	adev->smu_workload.initialized = false;
	mutex_destroy(&adev->smu_workload.workload_lock);
}
