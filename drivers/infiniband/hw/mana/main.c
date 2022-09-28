// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, Microsoft Corporation. All rights reserved.
 */

#include "mana_ib.h"

void mana_ib_uncfg_vport(struct mana_ib_dev *dev, struct mana_ib_pd *pd,
			 u32 port)
{
	struct gdma_dev *gd = dev->gdma_dev;
	struct mana_port_context *mpc;
	struct net_device *ndev;
	struct mana_context *mc;

	mc = gd->driver_data;
	ndev = mc->ports[port];
	mpc = netdev_priv(ndev);

	mutex_lock(&pd->vport_mutex);

	pd->vport_use_count--;
	WARN_ON(pd->vport_use_count < 0);

	if (!pd->vport_use_count)
		mana_uncfg_vport(mpc);

	mutex_unlock(&pd->vport_mutex);
}

int mana_ib_cfg_vport(struct mana_ib_dev *dev, u32 port, struct mana_ib_pd *pd,
		      u32 doorbell_id)
{
	struct gdma_dev *mdev = dev->gdma_dev;
	struct mana_port_context *mpc;
	struct mana_context *mc;
	struct net_device *ndev;
	int err;

	mc = mdev->driver_data;
	ndev = mc->ports[port];
	mpc = netdev_priv(ndev);

	mutex_lock(&pd->vport_mutex);

	pd->vport_use_count++;
	if (pd->vport_use_count > 1) {
		ibdev_dbg(&dev->ib_dev,
			  "Skip as this PD is already configured vport\n");
		mutex_unlock(&pd->vport_mutex);
		return 0;
	}
	mutex_unlock(&pd->vport_mutex);

	err = mana_cfg_vport(mpc, pd->pdn, doorbell_id);
	if (err) {
		mutex_lock(&pd->vport_mutex);
		pd->vport_use_count--;
		mutex_unlock(&pd->vport_mutex);

		ibdev_err(&dev->ib_dev, "Failed to configure vPort %d\n", err);
		return err;
	}

	pd->tx_shortform_allowed = mpc->tx_shortform_allowed;
	pd->tx_vp_offset = mpc->tx_vp_offset;

	ibdev_dbg(&dev->ib_dev,
		  "vport handle %llx pdid %x doorbell_id %x "
		  "tx_shortform_allowed %d tx_vp_offset %u\n",
		  mpc->port_handle, pd->pdn, doorbell_id,
		  pd->tx_shortform_allowed, pd->tx_vp_offset);

	return 0;
}

int mana_ib_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct mana_ib_pd *pd = container_of(ibpd, struct mana_ib_pd, ibpd);
	struct ib_device *ibdev = ibpd->device;
	enum gdma_pd_flags flags = 0;
	struct mana_ib_dev *dev;
	int ret;

	dev = container_of(ibdev, struct mana_ib_dev, ib_dev);

	ret = mana_ib_gd_create_pd(dev, &pd->pd_handle, &pd->pdn, flags);
	if (ret) {
		ibdev_err(ibdev, "Failed to get pd id, err %d\n", ret);
		return ret;
	}

	mutex_init(&pd->vport_mutex);
	pd->vport_use_count = 0;
	return 0;
}

int mana_ib_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct mana_ib_pd *pd = container_of(ibpd, struct mana_ib_pd, ibpd);
	struct ib_device *ibdev = ibpd->device;
	struct mana_ib_dev *dev;

	dev = container_of(ibdev, struct mana_ib_dev, ib_dev);
	return mana_ib_gd_destroy_pd(dev, pd->pd_handle);
}

int mana_ib_alloc_ucontext(struct ib_ucontext *ibcontext,
			   struct ib_udata *udata)
{
	struct mana_ib_ucontext *ucontext =
		container_of(ibcontext, struct mana_ib_ucontext, ibucontext);
	struct ib_device *ibdev = ibcontext->device;
	struct mana_ib_dev *mdev;
	struct gdma_context *gc;
	struct gdma_dev *dev;
	int doorbell_page;
	int ret;

	mdev = container_of(ibdev, struct mana_ib_dev, ib_dev);
	dev = mdev->gdma_dev;
	gc = dev->gdma_context;

	/* Allocate a doorbell page index */
	ret = mana_gd_allocate_doorbell_page(gc, &doorbell_page);
	if (ret) {
		ibdev_err(ibdev, "Failed to allocate doorbell page %d\n", ret);
		return -ENOMEM;
	}

	ibdev_dbg(ibdev, "Doorbell page allocated %d\n", doorbell_page);

	ucontext->doorbell = doorbell_page;

	return 0;
}

void mana_ib_dealloc_ucontext(struct ib_ucontext *ibcontext)
{
	struct mana_ib_ucontext *mana_ucontext =
		container_of(ibcontext, struct mana_ib_ucontext, ibucontext);
	struct ib_device *ibdev = ibcontext->device;
	struct mana_ib_dev *mdev;
	struct gdma_context *gc;
	int ret;

	mdev = container_of(ibdev, struct mana_ib_dev, ib_dev);
	gc = mdev->gdma_dev->gdma_context;

	ret = mana_gd_destroy_doorbell_page(gc, mana_ucontext->doorbell);
	if (ret)
		ibdev_err(ibdev, "Failed to destroy doorbell page %d\n", ret);
}

int mana_ib_gd_create_dma_region(struct mana_ib_dev *dev, struct ib_umem *umem,
				 mana_handle_t *gdma_region, u64 page_sz)
{
	size_t num_pages_total = ib_umem_num_dma_blocks(umem, page_sz);
	struct gdma_dma_region_add_pages_req *add_req = NULL;
	struct gdma_create_dma_region_resp create_resp = {};
	struct gdma_create_dma_region_req *create_req;
	size_t num_pages_cur, num_pages_to_handle;
	unsigned int create_req_msg_size;
	struct hw_channel_context *hwc;
	struct ib_block_iter biter;
	size_t max_pgs_create_cmd;
	struct gdma_context *gc;
	struct gdma_dev *mdev;
	unsigned int i;
	int err;

	mdev = dev->gdma_dev;
	gc = mdev->gdma_context;
	hwc = gc->hwc.driver_data;
	max_pgs_create_cmd =
		(hwc->max_req_msg_size - sizeof(*create_req)) / sizeof(u64);

	num_pages_to_handle =
		min_t(size_t, num_pages_total, max_pgs_create_cmd);
	create_req_msg_size =
		struct_size(create_req, page_addr_list, num_pages_to_handle);

	create_req = kzalloc(create_req_msg_size, GFP_KERNEL);
	if (!create_req)
		return -ENOMEM;

	mana_gd_init_req_hdr(&create_req->hdr, GDMA_CREATE_DMA_REGION,
			     create_req_msg_size, sizeof(create_resp));

	create_req->length = umem->length;
	create_req->offset_in_page = umem->address & (page_sz - 1);
	create_req->gdma_page_type = order_base_2(page_sz) - PAGE_SHIFT;
	create_req->page_count = num_pages_total;
	create_req->page_addr_list_len = num_pages_to_handle;

	ibdev_dbg(&dev->ib_dev,
		  "size_dma_region %lu num_pages_total %lu, "
		  "page_sz 0x%llx offset_in_page %u\n",
		  umem->length, num_pages_total, page_sz,
		  create_req->offset_in_page);

	ibdev_dbg(&dev->ib_dev, "num_pages_to_handle %lu, gdma_page_type %u",
		  num_pages_to_handle, create_req->gdma_page_type);

	__rdma_umem_block_iter_start(&biter, umem, page_sz);

	for (i = 0; i < num_pages_to_handle; ++i) {
		dma_addr_t cur_addr;

		__rdma_block_iter_next(&biter);
		cur_addr = rdma_block_iter_dma_address(&biter);

		create_req->page_addr_list[i] = cur_addr;

		ibdev_dbg(&dev->ib_dev, "page num %u cur_addr 0x%llx\n", i,
			  cur_addr);
	}

	err = mana_gd_send_request(gc, create_req_msg_size, create_req,
				   sizeof(create_resp), &create_resp);
	kfree(create_req);

	if (err || create_resp.hdr.status) {
		ibdev_err(&dev->ib_dev,
			  "Failed to create DMA region: %d, 0x%x\n", err,
			  create_resp.hdr.status);
		if (!err)
			err = -EPROTO;

		goto error;
	}

	*gdma_region = create_resp.dma_region_handle;
	ibdev_dbg(&dev->ib_dev, "Created DMA region with handle 0x%llx\n",
		  *gdma_region);

	num_pages_cur = num_pages_to_handle;

	if (num_pages_cur < num_pages_total) {
		unsigned int add_req_msg_size;
		size_t max_pgs_add_cmd =
			(hwc->max_req_msg_size - sizeof(*add_req)) /
			sizeof(u64);

		num_pages_to_handle =
			min_t(size_t, num_pages_total - num_pages_cur,
			      max_pgs_add_cmd);

		/* Calculate the max num of pages that will be handled */
		add_req_msg_size = struct_size(add_req, page_addr_list,
					       num_pages_to_handle);

		add_req = kmalloc(add_req_msg_size, GFP_KERNEL);
		if (!add_req) {
			err = -ENOMEM;
			goto free_gdma_region;
		}

		while (num_pages_cur < num_pages_total) {
			struct gdma_general_resp add_resp = {};
			u32 expected_status = 0;

			if (num_pages_cur + num_pages_to_handle <
			    num_pages_total) {
				/* Status indicating more pages are needed */
				expected_status = GDMA_STATUS_MORE_ENTRIES;
			}

			memset(add_req, 0, add_req_msg_size);

			mana_gd_init_req_hdr(&add_req->hdr,
					     GDMA_DMA_REGION_ADD_PAGES,
					     add_req_msg_size,
					     sizeof(add_resp));
			add_req->dma_region_handle = *gdma_region;
			add_req->page_addr_list_len = num_pages_to_handle;

			for (i = 0; i < num_pages_to_handle; ++i) {
				dma_addr_t cur_addr =
					rdma_block_iter_dma_address(&biter);
				add_req->page_addr_list[i] = cur_addr;
				__rdma_block_iter_next(&biter);

				ibdev_dbg(&dev->ib_dev,
					  "page_addr_list %lu addr 0x%llx\n",
					  num_pages_cur + i, cur_addr);
			}

			err = mana_gd_send_request(gc, add_req_msg_size,
						   add_req, sizeof(add_resp),
						   &add_resp);
			if (!err || add_resp.hdr.status != expected_status) {
				ibdev_err(&dev->ib_dev,
					  "Failed put DMA pages %u: %d,0x%x\n",
					  i, err, add_resp.hdr.status);
				err = -EPROTO;
				break;
			}

			num_pages_cur += num_pages_to_handle;
			num_pages_to_handle =
				min_t(size_t, num_pages_total - num_pages_cur,
				      max_pgs_add_cmd);
			add_req_msg_size = sizeof(*add_req) +
					   num_pages_to_handle * sizeof(u64);
		}

		kfree(add_req);
	}

	if (!err)
		return 0;

free_gdma_region:
	mana_ib_gd_destroy_dma_region(dev, create_resp.dma_region_handle);

error:
	return err;
}

int mana_ib_gd_destroy_dma_region(struct mana_ib_dev *dev, u64 gdma_region)
{
	struct gdma_dev *mdev = dev->gdma_dev;
	struct gdma_context *gc;

	gc = mdev->gdma_context;
	ibdev_dbg(&dev->ib_dev, "destroy dma region 0x%llx\n", gdma_region);

	return mana_gd_destroy_dma_region(gc, gdma_region);
}

int mana_ib_gd_create_pd(struct mana_ib_dev *dev, u64 *pd_handle, u32 *pd_id,
			 enum gdma_pd_flags flags)
{
	struct gdma_dev *mdev = dev->gdma_dev;
	struct gdma_create_pd_resp resp = {};
	struct gdma_create_pd_req req = {};
	struct gdma_context *gc;
	int err;

	gc = mdev->gdma_context;

	mana_gd_init_req_hdr(&req.hdr, GDMA_CREATE_PD, sizeof(req),
			     sizeof(resp));

	req.flags = flags;
	err = mana_gd_send_request(gc, sizeof(req), &req, sizeof(resp), &resp);

	if (err || resp.hdr.status) {
		ibdev_err(&dev->ib_dev,
			  "Failed to get pd_id err %d status %u\n", err,
			  resp.hdr.status);
		if (!err)
			err = -EPROTO;

		return err;
	}

	*pd_handle = resp.pd_handle;
	*pd_id = resp.pd_id;
	ibdev_dbg(&dev->ib_dev, "pd_handle 0x%llx pd_id %d\n", *pd_handle,
		  *pd_id);

	return 0;
}

int mana_ib_gd_destroy_pd(struct mana_ib_dev *dev, u64 pd_handle)
{
	struct gdma_dev *mdev = dev->gdma_dev;
	struct gdma_destory_pd_resp resp = {};
	struct gdma_destroy_pd_req req = {};
	struct gdma_context *gc;
	int err;

	gc = mdev->gdma_context;

	mana_gd_init_req_hdr(&req.hdr, GDMA_DESTROY_PD, sizeof(req),
			     sizeof(resp));

	req.pd_handle = pd_handle;
	err = mana_gd_send_request(gc, sizeof(req), &req, sizeof(resp), &resp);

	if (err || resp.hdr.status) {
		ibdev_err(&dev->ib_dev,
			  "Failed to destroy pd_handle 0x%llx err %d status %u",
			  pd_handle, err, resp.hdr.status);
		if (!err)
			err = -EPROTO;
	}

	return err;
}

int mana_ib_gd_create_mr(struct mana_ib_dev *dev, struct mana_ib_mr *mr,
			 struct gdma_create_mr_params *mr_params)
{
	struct gdma_create_mr_response resp = {};
	struct gdma_create_mr_request req = {};
	struct gdma_dev *mdev = dev->gdma_dev;
	struct gdma_context *gc;
	int err;

	gc = mdev->gdma_context;

	mana_gd_init_req_hdr(&req.hdr, GDMA_CREATE_MR, sizeof(req),
			     sizeof(resp));
	req.pd_handle = mr_params->pd_handle;
	req.mr_type = mr_params->mr_type;

	switch (mr_params->mr_type) {
	case GDMA_MR_TYPE_GVA:
		req.gva.dma_region_handle = mr_params->gva.dma_region_handle;
		req.gva.virtual_address = mr_params->gva.virtual_address;
		req.gva.access_flags = mr_params->gva.access_flags;
		break;

	default:
		ibdev_dbg(&dev->ib_dev,
			  "invalid param (GDMA_MR_TYPE) passed, type %d\n",
			  req.mr_type);
		err = -EINVAL;
		goto error;
	}

	err = mana_gd_send_request(gc, sizeof(req), &req, sizeof(resp), &resp);

	if (err || resp.hdr.status) {
		ibdev_err(&dev->ib_dev, "Failed to create mr %d, %u", err,
			  resp.hdr.status);
		if (!err)
			err = -EPROTO;

		goto error;
	}

	mr->ibmr.lkey = resp.lkey;
	mr->ibmr.rkey = resp.rkey;
	mr->mr_handle = resp.mr_handle;

	return 0;
error:
	return err;
}

int mana_ib_gd_destroy_mr(struct mana_ib_dev *dev, gdma_obj_handle_t mr_handle)
{
	struct gdma_destroy_mr_response resp = {};
	struct gdma_destroy_mr_request req = {};
	struct gdma_dev *mdev = dev->gdma_dev;
	struct gdma_context *gc;
	int err;

	gc = mdev->gdma_context;

	mana_gd_init_req_hdr(&req.hdr, GDMA_DESTROY_MR, sizeof(req),
			     sizeof(resp));

	req.mr_handle = mr_handle;

	err = mana_gd_send_request(gc, sizeof(req), &req, sizeof(resp), &resp);
	if (err || resp.hdr.status) {
		dev_err(gc->dev, "Failed to destroy MR: %d, 0x%x\n", err,
			resp.hdr.status);
		if (!err)
			err = -EPROTO;
		return err;
	}

	return 0;
}

int mana_ib_mmap(struct ib_ucontext *ibcontext, struct vm_area_struct *vma)
{
	struct mana_ib_ucontext *mana_ucontext =
		container_of(ibcontext, struct mana_ib_ucontext, ibucontext);
	struct ib_device *ibdev = ibcontext->device;
	struct mana_ib_dev *mdev;
	struct gdma_context *gc;
	phys_addr_t pfn;
	pgprot_t prot;
	int ret;

	mdev = container_of(ibdev, struct mana_ib_dev, ib_dev);
	gc = mdev->gdma_dev->gdma_context;

	if (vma->vm_pgoff != 0) {
		ibdev_err(ibdev, "Unexpected vm_pgoff %lu\n", vma->vm_pgoff);
		return -EINVAL;
	}

	/* Map to the page indexed by ucontext->doorbell */
	pfn = (gc->phys_db_page_base +
	       gc->db_page_size * mana_ucontext->doorbell) >>
	      PAGE_SHIFT;
	prot = pgprot_writecombine(vma->vm_page_prot);

	ret = rdma_user_mmap_io(ibcontext, vma, pfn, gc->db_page_size, prot,
				NULL);
	if (ret)
		ibdev_err(ibdev, "can't rdma_user_mmap_io ret %d\n", ret);
	else
		ibdev_dbg(ibdev, "mapped I/O pfn 0x%llx page_size %u, ret %d\n",
			  pfn, gc->db_page_size, ret);

	return ret;
}

int mana_ib_get_port_immutable(struct ib_device *ibdev, u32 port_num,
			       struct ib_port_immutable *immutable)
{
	/* This version only support RAW_PACKET
	 * other values need to be filled for other types
	 */
	immutable->core_cap_flags = RDMA_CORE_PORT_RAW_PACKET;

	return 0;
}

int mana_ib_query_device(struct ib_device *ibdev, struct ib_device_attr *props,
			 struct ib_udata *uhw)
{
	props->max_qp = MANA_MAX_NUM_QUEUES;
	props->max_qp_wr = MAX_SEND_BUFFERS_PER_QUEUE;

	/* max_cqe could be potentially much bigger.
	 * As this version of driver only support RAW QP, set it to the same
	 * value as max_qp_wr
	 */
	props->max_cqe = MAX_SEND_BUFFERS_PER_QUEUE;

	props->max_mr_size = MANA_IB_MAX_MR_SIZE;
	props->max_mr = INT_MAX;
	props->max_send_sge = MAX_TX_WQE_SGL_ENTRIES;
	props->max_recv_sge = MAX_RX_WQE_SGL_ENTRIES;

	return 0;
}

int mana_ib_query_port(struct ib_device *ibdev, u32 port,
		       struct ib_port_attr *props)
{
	/* This version doesn't return port properties */
	return 0;
}

int mana_ib_query_gid(struct ib_device *ibdev, u32 port, int index,
		      union ib_gid *gid)
{
	/* This version doesn't return GID properties */
	return 0;
}

void mana_ib_disassociate_ucontext(struct ib_ucontext *ibcontext)
{
}
