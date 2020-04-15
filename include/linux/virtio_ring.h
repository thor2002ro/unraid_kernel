/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_RING_H
#define _LINUX_VIRTIO_RING_H

#include <asm/barrier.h>
#include <linux/irqreturn.h>
#include <uapi/linux/virtio_ring.h>

/*
 * Barriers in virtio are tricky.  Non-SMP virtio guests can't assume
 * they're not on an SMP host system, so they need to assume real
 * barriers.  Non-SMP virtio hosts could skip the barriers, but does
 * anyone care?
 *
 * For virtio_pci on SMP, we don't need to order with respect to MMIO
 * accesses through relaxed memory I/O windows, so virt_mb() et al are
 * sufficient.
 *
 * For using virtio to talk to real devices (eg. other heterogeneous
 * CPUs) we do need real barriers.  In theory, we could be using both
 * kinds of virtio, so it's a runtime decision, and the branch is
 * actually quite cheap.
 */

static inline void virtio_mb(bool weak_barriers)
{
	if (weak_barriers)
		virt_mb();
	else
		mb();
}

static inline void virtio_rmb(bool weak_barriers)
{
	if (weak_barriers)
		virt_rmb();
	else
		dma_rmb();
}

static inline void virtio_wmb(bool weak_barriers)
{
	if (weak_barriers)
		virt_wmb();
	else
		dma_wmb();
}

static inline void virtio_store_mb(bool weak_barriers,
				   __virtio16 *p, __virtio16 v)
{
	if (weak_barriers) {
		virt_store_mb(*p, v);
	} else {
		WRITE_ONCE(*p, v);
		mb();
	}
}

struct virtio_device;
struct virtqueue;

/*
 * The ring element addresses are passed between components with different
 * alignments assumptions. Thus, we might need to decrease the compiler-selected
 * alignment, and so must use a typedef to make sure the __aligned attribute
 * actually takes hold:
 *
 * https://gcc.gnu.org/onlinedocs//gcc/Common-Type-Attributes.html#Common-Type-Attributes
 *
 * When used on a struct, or struct member, the aligned attribute can only
 * increase the alignment; in order to decrease it, the packed attribute must
 * be specified as well. When used as part of a typedef, the aligned attribute
 * can both increase and decrease alignment, and specifying the packed
 * attribute generates a warning.
 */
typedef struct vring_desc __aligned(VRING_DESC_ALIGN_SIZE) vring_desc_t;
typedef struct vring_avail __aligned(VRING_AVAIL_ALIGN_SIZE) vring_avail_t;
typedef struct vring_used __aligned(VRING_USED_ALIGN_SIZE) vring_used_t;

struct vring {
	unsigned int num;

	vring_desc_t *desc;

	vring_avail_t *avail;

	vring_used_t *used;
};

/*
 * Creates a virtqueue and allocates the descriptor ring.  If
 * may_reduce_num is set, then this may allocate a smaller ring than
 * expected.  The caller should query virtqueue_get_vring_size to learn
 * the actual size of the ring.
 */
struct virtqueue *vring_create_virtqueue(unsigned int index,
					 unsigned int num,
					 unsigned int vring_align,
					 struct virtio_device *vdev,
					 bool weak_barriers,
					 bool may_reduce_num,
					 bool ctx,
					 bool (*notify)(struct virtqueue *vq),
					 void (*callback)(struct virtqueue *vq),
					 const char *name);

/* Creates a virtqueue with a custom layout. */
struct virtqueue *__vring_new_virtqueue(unsigned int index,
					struct vring vring,
					struct virtio_device *vdev,
					bool weak_barriers,
					bool ctx,
					bool (*notify)(struct virtqueue *),
					void (*callback)(struct virtqueue *),
					const char *name);

/*
 * Creates a virtqueue with a standard layout but a caller-allocated
 * ring.
 */
struct virtqueue *vring_new_virtqueue(unsigned int index,
				      unsigned int num,
				      unsigned int vring_align,
				      struct virtio_device *vdev,
				      bool weak_barriers,
				      bool ctx,
				      void *pages,
				      bool (*notify)(struct virtqueue *vq),
				      void (*callback)(struct virtqueue *vq),
				      const char *name);

/*
 * Destroys a virtqueue.  If created with vring_create_virtqueue, this
 * also frees the ring.
 */
void vring_del_virtqueue(struct virtqueue *vq);

/* Filter out transport-specific feature bits. */
void vring_transport_features(struct virtio_device *vdev);

irqreturn_t vring_interrupt(int irq, void *_vq);

static inline void vring_legacy_init(struct vring *vr, unsigned int num, void *p,
				     unsigned long align)
{
	vr->num = num;
	vr->desc = p;
	vr->avail = (struct vring_avail *)((char *)p + num * sizeof(struct vring_desc));
	vr->used = (void *)(((uintptr_t)&vr->avail->ring[num] + sizeof(__virtio16)
		+ align-1) & ~(align - 1));
}

static inline unsigned vring_legacy_size(unsigned int num, unsigned long align)
{
	return ((sizeof(struct vring_desc) * num + sizeof(__virtio16) * (3 + num)
		 + align - 1) & ~(align - 1))
		+ sizeof(__virtio16) * 3 + sizeof(struct vring_used_elem) * num;
}

#endif /* _LINUX_VIRTIO_RING_H */
