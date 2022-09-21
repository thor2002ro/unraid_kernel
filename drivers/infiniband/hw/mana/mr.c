// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, Microsoft Corporation. All rights reserved.
 */

#include "mana_ib.h"

#define VALID_MR_FLAGS                                                         \
	(IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ)

static enum gdma_mr_access_flags
mana_ib_verbs_to_gdma_access_flags(int access_flags)
{
	enum gdma_mr_access_flags flags = GDMA_ACCESS_FLAG_LOCAL_READ;

	if (access_flags & IB_ACCESS_LOCAL_WRITE)
		flags |= GDMA_ACCESS_FLAG_LOCAL_WRITE;

	if (access_flags & IB_ACCESS_REMOTE_WRITE)
		flags |= GDMA_ACCESS_FLAG_REMOTE_WRITE;

	if (access_flags & IB_ACCESS_REMOTE_READ)
		flags |= GDMA_ACCESS_FLAG_REMOTE_READ;

	return flags;
}

struct ib_mr *mana_ib_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 length,
				  u64 iova, int access_flags,
				  struct ib_udata *udata)
{
	struct mana_ib_pd *pd = container_of(ibpd, struct mana_ib_pd, ibpd);
	struct gdma_create_mr_params mr_params = {};
	struct ib_device *ibdev = ibpd->device;
	gdma_obj_handle_t dma_region_handle;
	struct mana_ib_dev *dev;
	struct mana_ib_mr *mr;
	u64 page_sz;
	int err;

	dev = container_of(ibdev, struct mana_ib_dev, ib_dev);

	ibdev_dbg(ibdev,
		  "start 0x%llx, iova 0x%llx length 0x%llx access_flags 0x%x",
		  start, iova, length, access_flags);

	if (access_flags & ~VALID_MR_FLAGS)
		return ERR_PTR(-EINVAL);

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	mr->umem = ib_umem_get(ibdev, start, length, access_flags);
	if (IS_ERR(mr->umem)) {
		err = PTR_ERR(mr->umem);
		ibdev_dbg(ibdev,
			  "Failed to get umem for register user-mr, %d\n", err);
		goto err_free;
	}

	page_sz = ib_umem_find_best_pgsz(mr->umem, PAGE_SZ_BM, iova);
	if (unlikely(!page_sz)) {
		ibdev_err(ibdev, "Failed to get best page size\n");
		err = -EOPNOTSUPP;
		goto err_umem;
	}
	ibdev_dbg(ibdev, "Page size chosen %llu\n", page_sz);

	err = mana_ib_gd_create_dma_region(dev, mr->umem, &dma_region_handle,
					   page_sz);
	if (err) {
		ibdev_err(ibdev, "Failed create dma region for user-mr, %d\n",
			  err);
		goto err_umem;
	}

	ibdev_dbg(ibdev,
		  "mana_ib_gd_create_dma_region ret %d gdma_region %llx\n", err,
		  dma_region_handle);

	mr_params.pd_handle = pd->pd_handle;
	mr_params.mr_type = GDMA_MR_TYPE_GVA;
	mr_params.gva.dma_region_handle = dma_region_handle;
	mr_params.gva.virtual_address = iova;
	mr_params.gva.access_flags =
		mana_ib_verbs_to_gdma_access_flags(access_flags);

	err = mana_ib_gd_create_mr(dev, mr, &mr_params);
	if (err)
		goto err_dma_region;

	/* There is no need to keep track of dma_region_handle after MR is
	 * successfully created. The dma_region_handle is tracked in the PF
	 * as part of the lifecycle of this MR.
	 */

	mr->ibmr.length = length;
	mr->ibmr.page_size = page_sz;
	return &mr->ibmr;

err_dma_region:
	mana_gd_destroy_dma_region(dev->gdma_dev->gdma_context,
				   dma_region_handle);

err_umem:
	ib_umem_release(mr->umem);

err_free:
	kfree(mr);
	return ERR_PTR(err);
}

int mana_ib_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct mana_ib_mr *mr = container_of(ibmr, struct mana_ib_mr, ibmr);
	struct ib_device *ibdev = ibmr->device;
	struct mana_ib_dev *dev;
	int err;

	dev = container_of(ibdev, struct mana_ib_dev, ib_dev);

	err = mana_ib_gd_destroy_mr(dev, mr->mr_handle);
	if (err)
		return err;

	if (mr->umem)
		ib_umem_release(mr->umem);

	kfree(mr);

	return 0;
}
