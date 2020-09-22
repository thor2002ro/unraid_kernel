// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ntfs3/frecord.c
 *
 * Copyright (C) 2019-2020 Paragon Software GmbH, All rights reserved.
 *
 */

#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/nls.h>
#include <linux/sched/signal.h>

#include "debug.h"
#include "ntfs.h"
#include "ntfs_fs.h"

static inline void get_mi_ref(const struct mft_inode *mi, struct MFT_REF *ref)
{
#ifdef NTFS3_64BIT_CLUSTER
	ref->low = cpu_to_le32(mi->rno);
	ref->high = cpu_to_le16(mi->rno >> 32);
#else
	ref->low = cpu_to_le32(mi->rno);
	ref->high = 0;
#endif
	ref->seq = mi->mrec->seq;
}

static struct mft_inode *ni_ins_mi(struct ntfs_inode *ni, struct rb_root *tree,
				   CLST ino, struct rb_node *ins)
{
	struct rb_node **p = &tree->rb_node;
	struct rb_node *pr = NULL;

	while (*p) {
		struct mft_inode *mi;

		pr = *p;
		mi = rb_entry(pr, struct mft_inode, node);
		if (mi->rno > ino)
			p = &pr->rb_left;
		else if (mi->rno < ino)
			p = &pr->rb_right;
		else
			return mi;
	}

	if (!ins)
		return NULL;

	rb_link_node(ins, pr, p);
	rb_insert_color(ins, tree);
	return rb_entry(ins, struct mft_inode, node);
}

/*
 * ni_find_mi
 *
 * finds mft_inode by record number
 */
static struct mft_inode *ni_find_mi(struct ntfs_inode *ni, CLST rno)
{
	return ni_ins_mi(ni, &ni->mi_tree, rno, NULL);
}

/*
 * ni_add_mi
 *
 * adds new mft_inode into ntfs_inode
 */
static void ni_add_mi(struct ntfs_inode *ni, struct mft_inode *mi)
{
	ni_ins_mi(ni, &ni->mi_tree, mi->rno, &mi->node);
}

/*
 * ni_remove_mi
 *
 * removes mft_inode from ntfs_inode
 */
void ni_remove_mi(struct ntfs_inode *ni, struct mft_inode *mi)
{
	rb_erase(&mi->node, &ni->mi_tree);
}

/*
 * ni_std
 *
 * returns pointer into std_info from primary record
 */
struct ATTR_STD_INFO *ni_std(struct ntfs_inode *ni)
{
	const struct ATTRIB *attr;

	attr = mi_find_attr(&ni->mi, NULL, ATTR_STD, NULL, 0, NULL);
	return attr ? resident_data_ex(attr, sizeof(struct ATTR_STD_INFO)) :
		      NULL;
}

/*
 * ni_std5
 *
 * returns pointer into std_info from primary record
 */
struct ATTR_STD_INFO5 *ni_std5(struct ntfs_inode *ni)
{
	const struct ATTRIB *attr;

	attr = mi_find_attr(&ni->mi, NULL, ATTR_STD, NULL, 0, NULL);

	return attr ? resident_data_ex(attr, sizeof(struct ATTR_STD_INFO5)) :
		      NULL;
}

/*
 * ni_clear
 *
 * clears resources allocated by ntfs_inode
 */
void ni_clear(struct ntfs_inode *ni)
{
	struct rb_node *node;

	if (!ni->vfs_inode.i_nlink && is_rec_inuse(ni->mi.mrec))
		ni_delete_all(ni);

	al_destroy(ni);

	for (node = rb_first(&ni->mi_tree); node;) {
		struct rb_node *next = rb_next(node);
		struct mft_inode *mi = rb_entry(node, struct mft_inode, node);

		rb_erase(node, &ni->mi_tree);
		mi_put(mi);
		node = next;
	}

	/* bad inode always has mode == S_IFREG */
	if (ni->ni_flags & NI_FLAG_DIR)
		indx_clear(&ni->dir);
	else
		run_close(&ni->file.run);

	mi_clear(&ni->mi);
}

/*
 * ni_load_mi_ex
 *
 * finds mft_inode by record number.
 */
int ni_load_mi_ex(struct ntfs_inode *ni, CLST rno, struct mft_inode **mi)
{
	int err;
	struct mft_inode *r;

	r = ni_find_mi(ni, rno);
	if (r)
		goto out;

	err = mi_get(ni->mi.sbi, rno, &r);
	if (err)
		return err;

	ni_add_mi(ni, r);

out:
	if (mi)
		*mi = r;
	return 0;
}

/*
 * ni_load_mi
 *
 * load mft_inode corresponded list_entry
 */
int ni_load_mi(struct ntfs_inode *ni, struct ATTR_LIST_ENTRY *le,
	       struct mft_inode **mi)
{
	CLST rno;

	if (!le) {
		*mi = &ni->mi;
		return 0;
	}

	rno = ino_get(&le->ref);
	if (rno == ni->mi.rno) {
		*mi = &ni->mi;
		return 0;
	}
	return ni_load_mi_ex(ni, rno, mi);
}

/*
 * ni_find_attr
 *
 * returns attribute and record this attribute belongs to
 */
struct ATTRIB *ni_find_attr(struct ntfs_inode *ni, struct ATTRIB *attr,
			    struct ATTR_LIST_ENTRY **le_o, enum ATTR_TYPE type,
			    const __le16 *name, u8 name_len, const CLST *vcn,
			    struct mft_inode **mi)
{
	struct ATTR_LIST_ENTRY *le;
	struct mft_inode *m;

	if (!ni->attr_list.size ||
	    (!name_len && (type == ATTR_LIST || type == ATTR_STD))) {
		if (le_o)
			*le_o = NULL;
		if (mi)
			*mi = &ni->mi;

		/* Look for required attribute in primary record */
		return mi_find_attr(&ni->mi, attr, type, name, name_len, NULL);
	}

	/* first look for list entry of required type */
	le = al_find_ex(ni, le_o ? *le_o : NULL, type, name, name_len, vcn);
	if (!le)
		return NULL;

	if (le_o)
		*le_o = le;

	/* Load record that contains this attribute */
	if (ni_load_mi(ni, le, &m))
		return NULL;

	/* Look for required attribute */
	attr = mi_find_attr(m, NULL, type, name, name_len, &le->id);

	if (!attr)
		goto out;

	if (!attr->non_res) {
		if (vcn && *vcn)
			goto out;
	} else if (!vcn) {
		if (attr->nres.svcn)
			goto out;
	} else if (le64_to_cpu(attr->nres.svcn) > *vcn ||
		   *vcn > le64_to_cpu(attr->nres.evcn)) {
		goto out;
	}

	if (mi)
		*mi = m;
	return attr;

out:
	ntfs_set_state(ni->mi.sbi, NTFS_DIRTY_ERROR);
	return NULL;
}

/*
 * ni_enum_attr_ex
 *
 * enumerates attributes in ntfs_inode
 */
struct ATTRIB *ni_enum_attr_ex(struct ntfs_inode *ni, struct ATTRIB *attr,
			       struct ATTR_LIST_ENTRY **le)
{
	struct mft_inode *mi;
	struct ATTR_LIST_ENTRY *le2;

	/* Do we have an attribute list? */
	if (!ni->attr_list.size) {
		*le = NULL;
		/* Enum attributes in primary record */
		return mi_enum_attr(&ni->mi, attr);
	}

	/* get next list entry */
	le2 = *le = al_enumerate(ni, attr ? *le : NULL);
	if (!le2)
		return NULL;

	/* Load record that contains the required attribute */
	if (ni_load_mi(ni, le2, &mi))
		return NULL;

	/* Find attribute in loaded record */
	attr = rec_find_attr_le(mi, le2);
	return attr;
}

/*
 * ni_load_attr
 *
 * loads attribute that contains given vcn
 */
struct ATTRIB *ni_load_attr(struct ntfs_inode *ni, enum ATTR_TYPE type,
			    const __le16 *name, u8 name_len, CLST vcn,
			    struct mft_inode **pmi)
{
	struct ATTR_LIST_ENTRY *le;
	struct ATTRIB *attr;
	struct mft_inode *mi;
	struct ATTR_LIST_ENTRY *next;

	if (!ni->attr_list.size) {
		if (pmi)
			*pmi = &ni->mi;
		return mi_find_attr(&ni->mi, NULL, type, name, name_len, NULL);
	}

	le = al_find_ex(ni, NULL, type, name, name_len, NULL);
	if (!le)
		return NULL;

	/*
	 * Unfortunately ATTR_LIST_ENTRY contains only start vcn
	 * So to find the ATTRIB segment that contains 'vcn' we should
	 * enumerate some entries
	 */
	if (vcn) {
		for (;; le = next) {
			next = al_find_ex(ni, le, type, name, name_len, NULL);
			if (!next || le64_to_cpu(next->vcn) > vcn)
				break;
		}
	}

	if (ni_load_mi(ni, le, &mi))
		return NULL;

	if (pmi)
		*pmi = mi;

	attr = mi_find_attr(mi, NULL, type, name, name_len, &le->id);
	if (!attr)
		return NULL;

	if (!attr->non_res)
		return attr;

	if (le64_to_cpu(attr->nres.svcn) <= vcn &&
	    vcn <= le64_to_cpu(attr->nres.evcn))
		return attr;

	return NULL;
}

/*
 * ni_load_all_mi
 *
 * loads all subrecords
 */
int ni_load_all_mi(struct ntfs_inode *ni)
{
	int err;
	struct ATTR_LIST_ENTRY *le;

	if (!ni->attr_list.size)
		return 0;

	le = NULL;

	while ((le = al_enumerate(ni, le))) {
		CLST rno = ino_get(&le->ref);

		if (rno == ni->mi.rno)
			continue;

		err = ni_load_mi_ex(ni, rno, NULL);
		if (err)
			return err;
	}

	return 0;
}

/*
 * ni_add_subrecord
 *
 * allocate + format + attach a new subrecord
 */
bool ni_add_subrecord(struct ntfs_inode *ni, CLST rno, struct mft_inode **mi)
{
	struct mft_inode *m;

	m = ntfs_alloc(sizeof(struct mft_inode), 1);
	if (!m)
		return false;

	if (mi_format_new(m, ni->mi.sbi, rno, 0, ni->mi.rno == MFT_REC_MFT)) {
		mi_put(m);
		return false;
	}

	get_mi_ref(&ni->mi, &m->mrec->parent_ref);

	ni_add_mi(ni, m);
	*mi = m;
	return true;
}

/*
 * ni_remove_attr
 *
 * removes all attributes for the given type/name/id
 */
int ni_remove_attr(struct ntfs_inode *ni, enum ATTR_TYPE type,
		   const __le16 *name, size_t name_len, bool base_only,
		   const __le16 *id)
{
	int err;
	struct ATTRIB *attr;
	struct ATTR_LIST_ENTRY *le;
	struct mft_inode *mi;
	u32 type_in;
	int diff;

	if (base_only || type == ATTR_LIST || !ni->attr_list.size) {
		attr = mi_find_attr(&ni->mi, NULL, type, name, name_len, id);
		if (!attr)
			return -ENOENT;

		mi_remove_attr(&ni->mi, attr);
		return 0;
	}

	type_in = le32_to_cpu(type);
	le = NULL;

	for (;;) {
		le = al_enumerate(ni, le);
		if (!le)
			return 0;

next_le2:
		diff = le32_to_cpu(le->type) - type_in;
		if (diff < 0)
			continue;

		if (diff > 0)
			return 0;

		if (le->name_len != name_len)
			continue;

		if (name_len &&
		    memcmp(le_name(le), name, name_len * sizeof(short)))
			continue;

		if (id && le->id != *id)
			continue;
		err = ni_load_mi(ni, le, &mi);
		if (err)
			return err;

		al_remove_le(ni, le);

		attr = mi_find_attr(mi, NULL, type, name, name_len, id);
		if (!attr)
			return -ENOENT;

		mi_remove_attr(mi, attr);

		if (PtrOffset(ni->attr_list.le, le) >= ni->attr_list.size)
			return 0;
		goto next_le2;
	}
}

/*
 * ni_ins_new_attr
 *
 * inserts the attribute into record
 * Returns not full constructed attribute or NULL if not possible to create
 */
static struct ATTRIB *ni_ins_new_attr(struct ntfs_inode *ni,
				      struct mft_inode *mi,
				      struct ATTR_LIST_ENTRY *le,
				      enum ATTR_TYPE type, const __le16 *name,
				      u8 name_len, u32 asize, u16 name_off,
				      CLST svcn)
{
	int err;
	struct ATTRIB *attr;
	bool le_added = false;
	struct MFT_REF ref;

	get_mi_ref(mi, &ref);

	if (type != ATTR_LIST && !le && ni->attr_list.size) {
		err = al_add_le(ni, type, name, name_len, svcn, cpu_to_le16(-1),
				&ref, &le);
		if (err) {
			/* no memory or no space */
			return NULL;
		}
		le_added = true;

		/*
		 * al_add_le -> attr_set_size (list) -> ni_expand_list
		 * which moves some attributes out of primary record
		 * this means that name may point into moved memory
		 * reinit 'name' from le
		 */
		name = le->name;
	}

	attr = mi_insert_attr(mi, type, name, name_len, asize, name_off);
	if (!attr) {
		if (le_added)
			al_remove_le(ni, le);
		return NULL;
	}

	if (type == ATTR_LIST) {
		/*attr list is not in list entry array*/
		goto out;
	}

	if (!le)
		goto out;

	/* Update ATTRIB Id and record reference */
	le->id = attr->id;
	ni->attr_list.dirty = true;
	le->ref = ref;

out:

	return attr;
}

/*
 * ni_create_attr_list
 *
 * generates an attribute list for this primary record
 */
int ni_create_attr_list(struct ntfs_inode *ni)
{
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	int err;
	u32 lsize;
	struct ATTRIB *attr;
	struct ATTRIB *arr_move[7];
	struct ATTR_LIST_ENTRY *le, *le_b[7];
	struct MFT_REC *rec;
	bool is_mft;
	CLST rno = 0;
	struct mft_inode *mi;
	u32 free_b, nb, to_free, rs;
	u16 sz;

	is_mft = ni->mi.rno == MFT_REC_MFT;
	rec = ni->mi.mrec;
	rs = sbi->record_size;

	/*
	 * Skip estimating exact memory requirement
	 * Looks like one record_size is always enough
	 */
	le = ntfs_alloc(al_aligned(rs), 0);
	if (!le) {
		err = -ENOMEM;
		goto out;
	}

	get_mi_ref(&ni->mi, &le->ref);
	ni->attr_list.le = le;

	attr = NULL;
	nb = 0;
	free_b = 0;
	attr = NULL;

	for (; (attr = mi_enum_attr(&ni->mi, attr)); le = Add2Ptr(le, sz)) {
		sz = le_size(attr->name_len);
		WARN_ON(PtrOffset(ni->attr_list.le, le) + sz > rs);

		le->type = attr->type;
		le->size = cpu_to_le16(sz);
		le->name_len = attr->name_len;
		le->name_off = offsetof(struct ATTR_LIST_ENTRY, name);
		le->vcn = 0;
		if (le != ni->attr_list.le)
			le->ref = ni->attr_list.le->ref;
		le->id = attr->id;

		if (attr->name_len)
			memcpy(le->name, attr_name(attr),
			       sizeof(short) * attr->name_len);
		else if (attr->type == ATTR_STD)
			continue;
		else if (attr->type == ATTR_LIST)
			continue;
		else if (is_mft && attr->type == ATTR_DATA)
			continue;

		if (!nb || nb < ARRAY_SIZE(arr_move)) {
			le_b[nb] = le;
			arr_move[nb++] = attr;
			free_b += le32_to_cpu(attr->size);
		}
	}

	lsize = PtrOffset(ni->attr_list.le, le);
	ni->attr_list.size = lsize;

	to_free = le32_to_cpu(rec->used) + lsize + SIZEOF_RESIDENT;
	if (to_free <= rs) {
		to_free = 0;
	} else {
		to_free -= rs;

		if (to_free > free_b) {
			err = -EINVAL;
			goto out1;
		}
	}

	/* Allocate child mft. */
	err = ntfs_look_free_mft(sbi, &rno, is_mft, ni, &mi);
	if (err)
		goto out1;

	/* Call 'mi_remove_attr' in reverse order to keep pointers 'arr_move' valid */
	while (to_free > 0) {
		struct ATTRIB *b = arr_move[--nb];
		u32 asize = le32_to_cpu(b->size);
		u16 name_off = le16_to_cpu(b->name_off);

		attr = mi_insert_attr(mi, b->type, Add2Ptr(b, name_off),
				      b->name_len, asize, name_off);
		WARN_ON(!attr);

		get_mi_ref(mi, &le_b[nb]->ref);
		le_b[nb]->id = attr->id;

		/* copy all except id */
		memcpy(attr, b, asize);
		attr->id = le_b[nb]->id;

		WARN_ON(!mi_remove_attr(&ni->mi, b));

		if (to_free <= asize)
			break;
		to_free -= asize;
		WARN_ON(!nb);
	}

	attr = mi_insert_attr(&ni->mi, ATTR_LIST, NULL, 0,
			      lsize + SIZEOF_RESIDENT, SIZEOF_RESIDENT);
	WARN_ON(!attr);

	attr->non_res = 0;
	attr->flags = 0;
	attr->res.data_size = cpu_to_le32(lsize);
	attr->res.data_off = SIZEOF_RESIDENT_LE;
	attr->res.flags = 0;
	attr->res.res = 0;

	memcpy(resident_data_ex(attr, lsize), ni->attr_list.le, lsize);

	ni->attr_list.dirty = false;

	mark_inode_dirty(&ni->vfs_inode);
	goto out;

out1:
	ntfs_free(ni->attr_list.le);
	ni->attr_list.le = NULL;
	ni->attr_list.size = 0;

out:
	return err;
}

/*
 * ni_ins_attr_ext
 *
 * This method adds an external attribute to the ntfs_inode.
 */
static int ni_ins_attr_ext(struct ntfs_inode *ni, struct ATTR_LIST_ENTRY *le,
			   enum ATTR_TYPE type, const __le16 *name, u8 name_len,
			   u32 asize, CLST svcn, u16 name_off, bool force_ext,
			   struct ATTRIB **ins_attr, struct mft_inode **ins_mi)
{
	struct ATTRIB *attr;
	struct mft_inode *mi;
	CLST rno;
	u64 vbo;
	struct rb_node *node;
	int err;
	bool is_mft, is_mft_data;
	struct ntfs_sb_info *sbi = ni->mi.sbi;

	is_mft = ni->mi.rno == MFT_REC_MFT;
	is_mft_data = is_mft && type == ATTR_DATA && !name_len;

	if (asize > sbi->max_bytes_per_attr) {
		err = -EINVAL;
		goto out;
	}

	/*
	 * standard information and attr_list cannot be made external.
	 * The Log File cannot have any external attributes
	 */
	if (type == ATTR_STD || type == ATTR_LIST ||
	    ni->mi.rno == MFT_REC_LOG) {
		err = -EINVAL;
		goto out;
	}

	/* Create attribute list if it is not already existed */
	if (!ni->attr_list.size) {
		err = ni_create_attr_list(ni);
		if (err)
			goto out;
	}

	vbo = is_mft_data ? ((u64)svcn << sbi->cluster_bits) : 0;

	if (force_ext)
		goto insert_ext;

	/* Load all subrecords into memory. */
	err = ni_load_all_mi(ni);
	if (err)
		goto out;

	/* Check each of loaded subrecord */
	for (node = rb_first(&ni->mi_tree); node; node = rb_next(node)) {
		mi = rb_entry(node, struct mft_inode, node);

		if (is_mft_data &&
		    (mi_enum_attr(mi, NULL) ||
		     vbo <= ((u64)mi->rno << sbi->record_bits))) {
			/* We can't accept this record 'case MFT's bootstrapping */
			continue;
		}
		if (is_mft &&
		    mi_find_attr(mi, NULL, ATTR_DATA, NULL, 0, NULL)) {
			/*
			 * This child record already has a ATTR_DATA.
			 * So it can't accept any other records.
			 */
			continue;
		}

		if ((type != ATTR_NAME || name_len) &&
		    mi_find_attr(mi, NULL, type, name, name_len, NULL)) {
			/* Only indexed attributes can share same record */
			continue;
		}

		/* Try to insert attribute into this subrecord */
		attr = ni_ins_new_attr(ni, mi, le, type, name, name_len, asize,
				       name_off, svcn);
		if (!attr)
			continue;

		if (ins_attr)
			*ins_attr = attr;
		return 0;
	}

insert_ext:
	/* We have to allocate a new child subrecord*/
	err = ntfs_look_free_mft(sbi, &rno, is_mft_data, ni, &mi);
	if (err)
		goto out;

	if (is_mft_data && vbo <= ((u64)rno << sbi->record_bits)) {
		err = -EINVAL;
		goto out1;
	}

	attr = ni_ins_new_attr(ni, mi, le, type, name, name_len, asize,
			       name_off, svcn);
	if (!attr)
		goto out2;

	if (ins_attr)
		*ins_attr = attr;
	if (ins_mi)
		*ins_mi = mi;

	return 0;

out2:
	ni_remove_mi(ni, mi);
	mi_put(mi);
	err = -EINVAL;

out1:
	ntfs_mark_rec_free(sbi, rno);

out:
	return err;
}

/*
 * ni_insert_attr
 *
 * inserts an attribute into the file.
 *
 * If the primary record has room, it will just insert the attribute.
 * If not, it may make the attribute external.
 * For $MFT::Data it may make room for the attribute by
 * making other attributes external.
 *
 * NOTE:
 * The ATTR_LIST and ATTR_STD cannot be made external.
 * This function does not fill new attribute full
 * It only fills 'size'/'type'/'id'/'name_len' fields
 */
static int ni_insert_attr(struct ntfs_inode *ni, enum ATTR_TYPE type,
			  const __le16 *name, u8 name_len, u32 asize,
			  u16 name_off, CLST svcn, struct ATTRIB **ins_attr,
			  struct mft_inode **ins_mi)
{
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	int err;
	struct ATTRIB *attr, *eattr;
	struct MFT_REC *rec;
	bool is_mft;
	struct ATTR_LIST_ENTRY *le;
	u32 list_reserve, max_free, free, used, t32;
	__le16 id;
	u16 t16;

	is_mft = ni->mi.rno == MFT_REC_MFT;
	rec = ni->mi.mrec;

	list_reserve = SIZEOF_NONRESIDENT + 3 * (1 + 2 * sizeof(u32));
	used = le32_to_cpu(rec->used);
	free = sbi->record_size - used;

	if (is_mft && type != ATTR_LIST) {
		/* Reserve space for the ATTRIB List. */
		if (free < list_reserve)
			free = 0;
		else
			free -= list_reserve;
	}

	if (asize <= free) {
		attr = ni_ins_new_attr(ni, &ni->mi, NULL, type, name, name_len,
				       asize, name_off, svcn);
		if (attr) {
			if (ins_attr)
				*ins_attr = attr;
			if (ins_mi)
				*ins_mi = &ni->mi;
			err = 0;
			goto out;
		}
	}

	if (!is_mft || type != ATTR_DATA || svcn) {
		/* This ATTRIB will be external. */
		err = ni_ins_attr_ext(ni, NULL, type, name, name_len, asize,
				      svcn, name_off, false, ins_attr, ins_mi);
		goto out;
	}

	/*
	 * Here we have: "is_mft && type == ATTR_DATA && !svcn
	 *
	 * The first chunk of the $MFT::Data ATTRIB must be the base record.
	 * Evict as many other attributes as possible.
	 */
	max_free = free;

	/* Estimate the result of moving all possible attributes away.*/
	attr = NULL;

	while ((attr = mi_enum_attr(&ni->mi, attr))) {
		if (attr->type == ATTR_STD)
			continue;
		if (attr->type == ATTR_LIST)
			continue;
		max_free += le32_to_cpu(attr->size);
	}

	if (max_free < asize + list_reserve) {
		/* Impossible to insert this attribute into primary record */
		err = -EINVAL;
		goto out;
	}

	/* Start real attribute moving */
	attr = NULL;

	for (;;) {
		attr = mi_enum_attr(&ni->mi, attr);
		if (!attr) {
			/* We should never be here 'cause we have already check this case */
			err = -EINVAL;
			goto out;
		}

		/* Skip attributes that MUST be primary record */
		if (attr->type == ATTR_STD || attr->type == ATTR_LIST)
			continue;

		le = NULL;
		if (ni->attr_list.size) {
			le = al_find_le(ni, NULL, attr);
			if (!le) {
				/* Really this is a serious bug */
				err = -EINVAL;
				goto out;
			}
		}

		t32 = le32_to_cpu(attr->size);
		t16 = le16_to_cpu(attr->name_off);
		err = ni_ins_attr_ext(ni, le, attr->type, Add2Ptr(attr, t16),
				      attr->name_len, t32, attr_svcn(attr), t16,
				      false, &eattr, NULL);
		if (err)
			return err;

		id = eattr->id;
		memcpy(eattr, attr, t32);
		eattr->id = id;

		/* remove attrib from primary record */
		mi_remove_attr(&ni->mi, attr);

		/* attr now points to next attribute */
		if (attr->type == ATTR_END)
			goto out;
	}
	while (asize + list_reserve > sbi->record_size - le32_to_cpu(rec->used))
		;

	attr = ni_ins_new_attr(ni, &ni->mi, NULL, type, name, name_len, asize,
			       name_off, svcn);
	if (!attr) {
		err = -EINVAL;
		goto out;
	}

	if (ins_attr)
		*ins_attr = attr;
	if (ins_mi)
		*ins_mi = &ni->mi;

out:
	return err;
}

/*
 * ni_expand_mft_list
 *
 * This method splits ATTR_DATA of $MFT
 */
static int ni_expand_mft_list(struct ntfs_inode *ni)
{
	int err = 0;
	struct runs_tree *run = &ni->file.run;
	u32 asize, run_size, done = 0;
	struct ATTRIB *attr;
	struct rb_node *node;
	CLST mft_min, mft_new, svcn, evcn, plen;
	struct mft_inode *mi, *mi_min, *mi_new;
	struct ntfs_sb_info *sbi = ni->mi.sbi;

	/* Find the nearest Mft */
	mft_min = 0;
	mft_new = 0;
	mi_min = NULL;

	for (node = rb_first(&ni->mi_tree); node; node = rb_next(node)) {
		mi = rb_entry(node, struct mft_inode, node);

		attr = mi_enum_attr(mi, NULL);

		if (!attr) {
			mft_min = mi->rno;
			mi_min = mi;
			break;
		}
	}

	if (ntfs_look_free_mft(sbi, &mft_new, true, ni, &mi_new)) {
		mft_new = 0;
		// really this is not critical
	} else if (mft_min > mft_new) {
		mft_min = mft_new;
		mi_min = mi_new;
	} else {
		ntfs_mark_rec_free(sbi, mft_new);
		mft_new = 0;
		ni_remove_mi(ni, mi_new);
	}

	attr = mi_find_attr(&ni->mi, NULL, ATTR_DATA, NULL, 0, NULL);
	if (!attr) {
		err = -EINVAL;
		goto out;
	}

	asize = le32_to_cpu(attr->size);

	evcn = le64_to_cpu(attr->nres.evcn);
	svcn = bytes_to_cluster(sbi, (u64)(mft_min + 1) << sbi->record_bits);
	if (evcn + 1 >= svcn) {
		err = -EINVAL;
		goto out;
	}

	/*
	 * split primary attribute [0 evcn] in two parts [0 svcn) + [svcn evcn]
	 *
	 * Update first part of ATTR_DATA in 'primary MFT
	 */
	err = run_pack(run, 0, svcn, Add2Ptr(attr, SIZEOF_NONRESIDENT),
		       asize - SIZEOF_NONRESIDENT, &plen);
	if (err < 0)
		goto out;

	run_size = QuadAlign(err);
	err = 0;

	if (plen < svcn) {
		err = -EINVAL;
		goto out;
	}

	attr->nres.evcn = cpu_to_le64(svcn - 1);
	attr->size = cpu_to_le32(run_size + SIZEOF_NONRESIDENT);
	/* 'done' - how many bytes of primary MFT becomes free */
	done = asize - run_size - SIZEOF_NONRESIDENT;
	le32_sub_cpu(&ni->mi.mrec->used, done);

	/* Estimate the size of second part: run_buf=NULL */
	err = run_pack(run, svcn, evcn + 1 - svcn, NULL, sbi->record_size,
		       &plen);
	if (err < 0)
		goto out;

	run_size = QuadAlign(err);
	err = 0;

	if (plen < evcn + 1 - svcn) {
		err = -EINVAL;
		goto out;
	}

	/*
	 * This function may implicitly call expand attr_list
	 * Insert second part of ATTR_DATA in 'mi_min'
	 */
	attr = ni_ins_new_attr(ni, mi_min, NULL, ATTR_DATA, NULL, 0,
			       SIZEOF_NONRESIDENT + run_size,
			       SIZEOF_NONRESIDENT, svcn);
	if (!attr) {
		err = -EINVAL;
		goto out;
	}

	attr->non_res = 1;
	attr->name_off = SIZEOF_NONRESIDENT_LE;
	attr->flags = 0;

	run_pack(run, svcn, evcn + 1 - svcn, Add2Ptr(attr, SIZEOF_NONRESIDENT),
		 run_size, &plen);

	attr->nres.svcn = cpu_to_le64(svcn);
	attr->nres.evcn = cpu_to_le64(evcn);
	attr->nres.run_off = cpu_to_le16(SIZEOF_NONRESIDENT);

out:
	if (mft_new) {
		ntfs_mark_rec_free(sbi, mft_new);
		ni_remove_mi(ni, mi_new);
	}

	return !err && !done ? -EOPNOTSUPP : err;
}

/*
 * ni_expand_list
 *
 * This method moves all possible attributes out of primary record
 */
int ni_expand_list(struct ntfs_inode *ni)
{
	int err = 0;
	u32 asize, done = 0;
	struct ATTRIB *attr, *ins_attr;
	struct ATTR_LIST_ENTRY *le;
	bool is_mft = ni->mi.rno == MFT_REC_MFT;
	struct MFT_REF ref;

	get_mi_ref(&ni->mi, &ref);
	le = NULL;

	while ((le = al_enumerate(ni, le))) {
		if (le->type == ATTR_STD)
			continue;

		if (memcmp(&ref, &le->ref, sizeof(struct MFT_REF)))
			continue;

		if (is_mft && le->type == ATTR_DATA)
			continue;

		/* Find attribute in primary record */
		attr = rec_find_attr_le(&ni->mi, le);
		if (!attr) {
			err = -EINVAL;
			goto out;
		}

		asize = le32_to_cpu(attr->size);

		/* Always insert into new record to avoid collisions (deep recursive) */
		err = ni_ins_attr_ext(ni, le, attr->type, attr_name(attr),
				      attr->name_len, asize, attr_svcn(attr),
				      le16_to_cpu(attr->name_off), true,
				      &ins_attr, NULL);

		if (err)
			goto out;

		memcpy(ins_attr, attr, asize);
		ins_attr->id = le->id;
		mi_remove_attr(&ni->mi, attr);

		done += asize;
		goto out;
	}

	if (!is_mft) {
		err = -EFBIG; /* attr list is too big(?) */
		goto out;
	}

	/* split mft data as much as possible */
	err = ni_expand_mft_list(ni);
	if (err)
		goto out;

out:
	return !err && !done ? -EOPNOTSUPP : err;
}

/*
 * ni_insert_nonresident
 *
 * inserts new nonresident attribute
 */
int ni_insert_nonresident(struct ntfs_inode *ni, enum ATTR_TYPE type,
			  const __le16 *name, u8 name_len,
			  const struct runs_tree *run, CLST svcn, CLST len,
			  __le16 flags, struct ATTRIB **new_attr,
			  struct mft_inode **mi)
{
	int err;
	CLST plen;
	struct ATTRIB *attr;
	bool is_ext =
		(flags & (ATTR_FLAG_SPARSED | ATTR_FLAG_COMPRESSED)) && !svcn;
	u32 name_size = QuadAlign(name_len * sizeof(short));
	u32 name_off = is_ext ? SIZEOF_NONRESIDENT_EX : SIZEOF_NONRESIDENT;
	u32 run_off = name_off + name_size;
	u32 run_size, asize;
	struct ntfs_sb_info *sbi = ni->mi.sbi;

	err = run_pack(run, svcn, len, NULL, sbi->max_bytes_per_attr - run_off,
		       &plen);
	if (err < 0)
		goto out;

	run_size = QuadAlign(err);

	if (plen < len) {
		err = -EINVAL;
		goto out;
	}

	asize = run_off + run_size;

	if (asize > sbi->max_bytes_per_attr) {
		err = -EINVAL;
		goto out;
	}

	err = ni_insert_attr(ni, type, name, name_len, asize, name_off, svcn,
			     &attr, mi);

	if (err)
		goto out;

	attr->non_res = 1;
	attr->name_off = cpu_to_le16(name_off);
	attr->flags = flags;

	run_pack(run, svcn, len, Add2Ptr(attr, run_off), run_size, &plen);

	attr->nres.svcn = cpu_to_le64(svcn);
	attr->nres.evcn = cpu_to_le64((u64)svcn + len - 1);

	err = 0;
	if (new_attr)
		*new_attr = attr;

	*(__le64 *)&attr->nres.run_off = cpu_to_le64(run_off);

	attr->nres.alloc_size =
		svcn ? 0 : cpu_to_le64((u64)len << ni->mi.sbi->cluster_bits);
	attr->nres.data_size = attr->nres.alloc_size;
	attr->nres.valid_size = attr->nres.alloc_size;

	if (is_ext) {
		if (flags & ATTR_FLAG_COMPRESSED)
			attr->nres.c_unit = COMPRESSION_UNIT;
		attr->nres.total_size = attr->nres.alloc_size;
	}

out:
	return err;
}

/*
 * ni_insert_resident
 *
 * inserts new resident attribute
 */
int ni_insert_resident(struct ntfs_inode *ni, u32 data_size,
		       enum ATTR_TYPE type, const __le16 *name, u8 name_len,
		       struct ATTRIB **new_attr, struct mft_inode **mi)
{
	int err;
	u32 name_size = QuadAlign(name_len * sizeof(short));
	u32 asize = SIZEOF_RESIDENT + name_size + QuadAlign(data_size);
	struct ATTRIB *attr;

	err = ni_insert_attr(ni, type, name, name_len, asize, SIZEOF_RESIDENT,
			     0, &attr, mi);
	if (err)
		return err;

	attr->non_res = 0;
	attr->flags = 0;

	attr->res.data_size = cpu_to_le32(data_size);
	attr->res.data_off = cpu_to_le16(SIZEOF_RESIDENT + name_size);
	if (type == ATTR_NAME)
		attr->res.flags = RESIDENT_FLAG_INDEXED;
	attr->res.res = 0;

	if (new_attr)
		*new_attr = attr;

	return 0;
}

/*
 * ni_remove_attr_le
 *
 * removes attribute from record
 */
int ni_remove_attr_le(struct ntfs_inode *ni, struct ATTRIB *attr,
		      struct ATTR_LIST_ENTRY *le)
{
	int err;
	struct mft_inode *mi;

	err = ni_load_mi(ni, le, &mi);
	if (err)
		return err;

	mi_remove_attr(mi, attr);

	if (le)
		al_remove_le(ni, le);

	return 0;
}

/*
 * ni_delete_all
 *
 * removes all attributes and frees allocates space
 * ntfs_evict_inode->ntfs_clear_inode->ni_delete_all (if no links)
 */
int ni_delete_all(struct ntfs_inode *ni)
{
	int err;
	struct ATTR_LIST_ENTRY *le = NULL;
	struct ATTRIB *attr = NULL;
	struct rb_node *node;
	u16 roff;
	u32 asize;
	CLST svcn, evcn;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	bool nt3 = is_ntfs3(sbi);
	struct MFT_REF ref;

	while ((attr = ni_enum_attr_ex(ni, attr, &le))) {
		if (!nt3 || attr->name_len) {
			;
		} else if (attr->type == ATTR_REPARSE) {
			get_mi_ref(&ni->mi, &ref);
			ntfs_remove_reparse(sbi, 0, &ref);
		} else if (attr->type == ATTR_ID && !attr->non_res &&
			   le32_to_cpu(attr->res.data_size) >=
				   sizeof(struct GUID)) {
			ntfs_objid_remove(sbi, resident_data(attr));
		}

		if (!attr->non_res)
			continue;

		svcn = le64_to_cpu(attr->nres.svcn);
		evcn = le64_to_cpu(attr->nres.evcn);

		if (evcn + 1 <= svcn)
			continue;

		asize = le32_to_cpu(attr->size);
		roff = le16_to_cpu(attr->nres.run_off);

		/*run==1 means unpack and deallocate*/
		run_unpack_ex((struct runs_tree *)(size_t)1, sbi, ni->mi.rno,
			      svcn, evcn, Add2Ptr(attr, roff), asize - roff);
	}

	if (ni->attr_list.size) {
		run_deallocate(ni->mi.sbi, &ni->attr_list.run, true);
		al_destroy(ni);
	}

	/* Free all subrecords */
	for (node = rb_first(&ni->mi_tree); node;) {
		struct rb_node *next = rb_next(node);
		struct mft_inode *mi = rb_entry(node, struct mft_inode, node);

		clear_rec_inuse(mi->mrec);
		mi->dirty = true;
		mi_write(mi, 0);

		ntfs_mark_rec_free(sbi, mi->rno);
		ni_remove_mi(ni, mi);
		mi_put(mi);
		node = next;
	}

	// Free base record
	clear_rec_inuse(ni->mi.mrec);
	ni->mi.dirty = true;
	err = mi_write(&ni->mi, 0);

	ntfs_mark_rec_free(sbi, ni->mi.rno);

	return err;
}

/*
 * ni_fname_name
 *
 * returns file name attribute by its value
 */
struct ATTR_FILE_NAME *ni_fname_name(struct ntfs_inode *ni,
				     const struct cpu_str *uni,
				     const struct MFT_REF *home_dir,
				     struct ATTR_LIST_ENTRY **le)
{
	struct ATTRIB *attr = NULL;
	struct ATTR_FILE_NAME *fname;

	*le = NULL;

	/* Enumerate all names */
next:
	attr = ni_find_attr(ni, attr, le, ATTR_NAME, NULL, 0, NULL, NULL);
	if (!attr)
		return NULL;

	fname = resident_data_ex(attr, SIZEOF_ATTRIBUTE_FILENAME);
	if (!fname)
		goto next;

	if (home_dir && memcmp(home_dir, &fname->home, sizeof(*home_dir)))
		goto next;

	if (!uni)
		goto next;

	if (uni->len != fname->name_len)
		goto next;

	if (ntfs_cmp_names_cpu(uni, (struct le_str *)&fname->name_len, NULL))
		goto next;

	return fname;
}

/*
 * ni_fname_type
 *
 * returns file name attribute with given type
 */
struct ATTR_FILE_NAME *ni_fname_type(struct ntfs_inode *ni, u8 name_type,
				     struct ATTR_LIST_ENTRY **le)
{
	struct ATTRIB *attr = NULL;
	struct ATTR_FILE_NAME *fname;

	*le = NULL;

	/* Enumerate all names */
	for (;;) {
		attr = ni_find_attr(ni, attr, le, ATTR_NAME, NULL, 0, NULL,
				    NULL);
		if (!attr)
			return NULL;

		fname = resident_data_ex(attr, SIZEOF_ATTRIBUTE_FILENAME);
		if (fname && name_type == fname->type)
			return fname;
	}
}

/*
 * ni_init_compress
 *
 * allocates and fill 'compress_ctx'
 * used to decompress lzx and xpress
 */
int ni_init_compress(struct ntfs_inode *ni, struct COMPRESS_CTX *ctx)
{
	u32 c_format = ((ni->ni_flags & NI_FLAG_COMPRESSED_MASK) >> 8) - 1;
	u32 chunk_bits;

	switch (c_format) {
	case WOF_COMPRESSION_XPRESS4K:
		chunk_bits = 12; // 4k
		break;
	case WOF_COMPRESSION_LZX:
		chunk_bits = 15; // 32k
		break;
	case WOF_COMPRESSION_XPRESS8K:
		chunk_bits = 13; // 8k
		break;
	case WOF_COMPRESSION_XPRESS16K:
		chunk_bits = 14; // 16k
		break;
	default:
		return -EOPNOTSUPP;
	}

	ctx->chunk_bits = chunk_bits;
	ctx->offset_bits = ni->vfs_inode.i_size < 0x100000000ull ?
				   2 :
				   3; // 32 or 64 bits per offsets

	ctx->compress_format = c_format;
	ctx->chunk_size = 1u << chunk_bits;
	ctx->chunk_num = -1;
	ctx->first_chunk = -1;
	ctx->total_chunks = (ni->vfs_inode.i_size - 1) >> chunk_bits;
	ctx->chunk0_off = ctx->total_chunks << ctx->offset_bits;

	return 0;
}

/*
 * ni_parse_reparse
 *
 * buffer is at least 24 bytes
 */
enum REPARSE_SIGN ni_parse_reparse(struct ntfs_inode *ni, struct ATTRIB *attr,
				   void *buffer)
{
	const struct REPARSE_DATA_BUFFER *rp = NULL;
	u32 c_format;
	u16 len;
	typeof(rp->CompressReparseBuffer) *cmpr;

	/* Try to estimate reparse point */
	if (!attr->non_res) {
		rp = resident_data_ex(attr, sizeof(struct REPARSE_DATA_BUFFER));
	} else if (le64_to_cpu(attr->nres.data_size) >=
		   sizeof(struct REPARSE_DATA_BUFFER)) {
		struct runs_tree run;

		run_init(&run);

		if (!attr_load_runs_vcn(ni, ATTR_REPARSE, NULL, 0, &run, 0) &&
		    !ntfs_read_run_nb(ni->mi.sbi, &run, 0, buffer,
				      sizeof(struct REPARSE_DATA_BUFFER),
				      NULL)) {
			rp = buffer;
		}

		run_close(&run);
	}

	if (!rp)
		return REPARSE_NONE;

	len = le16_to_cpu(rp->ReparseDataLength);
	switch (rp->ReparseTag) {
	case (IO_REPARSE_TAG_MICROSOFT | IO_REPARSE_TAG_SYMBOLIC_LINK):
		break; /* Symbolic link */
	case IO_REPARSE_TAG_MOUNT_POINT:
		break; /* Mount points and junctions */
	case IO_REPARSE_TAG_SYMLINK:
		break;
	case IO_REPARSE_TAG_COMPRESS:
		cmpr = &rp->CompressReparseBuffer;
		if (len < sizeof(*cmpr) ||
		    cmpr->WofVersion != WOF_CURRENT_VERSION ||
		    cmpr->WofProvider != WOF_PROVIDER_SYSTEM ||
		    cmpr->ProviderVer != WOF_PROVIDER_CURRENT_VERSION) {
			return REPARSE_NONE;
		}
		c_format = le32_to_cpu(cmpr->CompressionFormat);
		if (c_format > 3)
			return REPARSE_NONE;

		ni->ni_flags |= (c_format + 1) << 8;
		return REPARSE_COMPRESSED;

	case IO_REPARSE_TAG_DEDUP:
		ni->ni_flags |= NI_FLAG_DEDUPLICATED;
		return REPARSE_DEDUPLICATED;

	default:
		if (rp->ReparseTag & IO_REPARSE_TAG_NAME_SURROGATE)
			break;

		return REPARSE_NONE;
	}

	/* Looks like normal symlink */
	return REPARSE_LINK;
}

/*
 * helper for file_fiemap
 * assumed ni_lock
 * TODO: less aggressive locks
 */
int ni_fiemap(struct ntfs_inode *ni, struct fiemap_extent_info *fieinfo,
	      __u64 vbo, __u64 len)
{
	int err = 0;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	u8 cluster_bits = sbi->cluster_bits;
	struct runs_tree *run;
	struct rw_semaphore *run_lock;
	struct ATTRIB *attr;
	CLST vcn = vbo >> cluster_bits;
	CLST lcn, clen;
	u64 valid = ni->i_valid;
	u64 lbo, bytes;
	u64 end, alloc_size;
	size_t idx = -1;
	u32 flags;
	bool ok;

	if (S_ISDIR(ni->vfs_inode.i_mode)) {
		run = &ni->dir.alloc_run;
		attr = ni_find_attr(ni, NULL, NULL, ATTR_ALLOC, I30_NAME,
				    ARRAY_SIZE(I30_NAME), NULL, NULL);
		run_lock = NULL;
	} else {
		run = &ni->file.run;
		attr = ni_find_attr(ni, NULL, NULL, ATTR_DATA, NULL, 0, NULL,
				    NULL);
		if (!attr) {
			err = -EINVAL;
			goto out;
		}
		run_lock = &ni->file.run_lock;
	}

	if (!attr || !attr->non_res) {
		err = fiemap_fill_next_extent(
			fieinfo, 0, 0,
			attr ? le32_to_cpu(attr->res.data_size) : 0,
			FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_LAST |
				FIEMAP_EXTENT_MERGED);
		goto out;
	}

	end = vbo + len;
	alloc_size = le64_to_cpu(attr->nres.alloc_size);
	if (end > alloc_size)
		end = alloc_size;

	if (run_lock)
		down_read(run_lock);

	while (vbo < end) {
		if (idx == -1) {
			ok = run_lookup_entry(run, vcn, &lcn, &clen, &idx);
		} else {
			CLST next_vcn = vcn;

			ok = run_get_entry(run, ++idx, &vcn, &lcn, &clen);
			if (ok && vcn != next_vcn) {
				ok = false;
				vcn = next_vcn;
			}
		}

		if (!ok) {
			if (run_lock) {
				up_read(run_lock);
				down_write(run_lock);
			}

			err = attr_load_runs_vcn(ni, attr->type,
						 attr_name(attr),
						 attr->name_len, run, vcn);

			if (run_lock) {
				up_write(run_lock);
				down_read(run_lock);
			}

			if (err)
				break;

			ok = run_lookup_entry(run, vcn, &lcn, &clen, &idx);

			if (!ok) {
				err = -EINVAL;
				break;
			}
		}

		if (!clen) {
			err = -EINVAL; // ?
			break;
		}

		if (lcn == SPARSE_LCN) {
			vcn += clen;
			vbo = (u64)vcn << cluster_bits;
			continue;
		}

		flags = FIEMAP_EXTENT_MERGED;
		if (S_ISDIR(ni->vfs_inode.i_mode)) {
			;
		} else if (is_attr_compressed(attr)) {
			bool is_compr;
			CLST clst_data;

			err = attr_is_frame_compressed(ni, attr,
						       vcn >> attr->nres.c_unit,
						       &clst_data, &is_compr);
			if (err)
				break;
			if (is_compr)
				flags |= FIEMAP_EXTENT_ENCODED;
		} else if (is_attr_encrypted(attr)) {
			flags |= FIEMAP_EXTENT_DATA_ENCRYPTED;
		}

		vbo = (u64)vcn << cluster_bits;
		bytes = (u64)clen << cluster_bits;
		lbo = (u64)lcn << cluster_bits;

		vcn += clen;

		if (vbo + bytes >= end) {
			bytes = end - vbo;
			flags |= FIEMAP_EXTENT_LAST;
		}

		if (vbo + bytes <= valid) {
			;
		} else if (vbo >= valid) {
			flags |= FIEMAP_EXTENT_UNWRITTEN;
		} else {
			/* vbo < valid && valid < vbo + bytes */
			u64 dlen = valid - vbo;

			err = fiemap_fill_next_extent(fieinfo, vbo, lbo, dlen,
						      flags);
			if (err < 0)
				break;
			if (err == 1) {
				err = 0;
				break;
			}

			vbo = valid;
			bytes -= dlen;
			if (!bytes)
				continue;

			lbo += dlen;
			flags |= FIEMAP_EXTENT_UNWRITTEN;
		}

		err = fiemap_fill_next_extent(fieinfo, vbo, lbo, bytes, flags);
		if (err < 0)
			break;
		if (err == 1) {
			err = 0;
			break;
		}

		vbo += bytes;
	}

	if (run_lock)
		up_read(run_lock);

out:
	return err;
}

/*
 * When decompressing, we typically obtain more than one page per reference.
 * We inject the additional pages into the page cache.
 */
int ni_readpage_cmpr(struct ntfs_inode *ni, struct page *page)
{
	int err;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct address_space *mapping = page->mapping;
	struct ATTR_LIST_ENTRY *le;
	struct ATTRIB *attr;
	u8 frame_bits;
	u32 frame_size, i, idx;
	CLST frame, clst_data;
	struct page *pg;
	pgoff_t index = page->index, end_index;
	u64 vbo = (u64)index << PAGE_SHIFT;
	u32 pages_per_frame = 0;
	struct page **pages = NULL;
	char *frame_buf = NULL;
	char *frame_unc;
	u32 cmpr_size, unc_size;
	u64 frame_vbo, valid_size;
	size_t unc_size_fin;
	struct COMPRESS_CTX *ctx = NULL;
	bool is_compr = false;

	end_index = (ni->vfs_inode.i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	if (index >= end_index) {
		SetPageUptodate(page);
		err = 0;
		goto out;
	}

	le = NULL;
	attr = ni_find_attr(ni, NULL, &le, ATTR_DATA, NULL, 0, NULL, NULL);
	if (!attr) {
		err = -ENOENT;
		goto out;
	}

	WARN_ON(!attr->non_res);

	if (ni->ni_flags & NI_FLAG_COMPRESSED_MASK) {
		ctx = ntfs_alloc(sizeof(*ctx), 1);
		if (!ctx) {
			err = -ENOMEM;
			goto out;
		}
		err = ni_init_compress(ni, ctx);
		if (err)
			goto out;

		frame_bits = ctx->chunk_bits;
		frame_size = ctx->chunk_size;
		frame = vbo >> frame_bits;
		frame_vbo = (u64)frame << frame_bits;

		/* TODO: port lzx/xpress */
		err = -EOPNOTSUPP;
		goto out;
	} else if (is_attr_compressed(attr)) {
		if (sbi->cluster_size > NTFS_LZNT_MAX_CLUSTER) {
			err = -EOPNOTSUPP;
			goto out;
		}

		if (attr->nres.c_unit != NTFS_LZNT_CUNIT) {
			err = -EOPNOTSUPP;
			goto out;
		}

		frame_bits = NTFS_LZNT_CUNIT + sbi->cluster_bits;
		frame_size = sbi->cluster_size << NTFS_LZNT_CUNIT;
		frame = vbo >> frame_bits;
		frame_vbo = (u64)frame << frame_bits;

		err = attr_is_frame_compressed(ni, attr, frame, &clst_data,
					       &is_compr);
		if (err)
			goto out;
	} else {
		WARN_ON(1);
		err = -EINVAL;
		goto out;
	}

	pages_per_frame = frame_size >> PAGE_SHIFT;
	pages = ntfs_alloc(pages_per_frame * sizeof(*pages), 1);
	if (!pages) {
		err = -ENOMEM;
		goto out;
	}

	idx = (vbo - frame_vbo) >> PAGE_SHIFT;
	pages[idx] = page;
	index = frame_vbo >> PAGE_SHIFT;
	kmap(page);

	for (i = 0; i < pages_per_frame && index < end_index; i++, index++) {
		if (i == idx)
			continue;

		pg = grab_cache_page_nowait(mapping, index);
		if (!pg)
			continue;

		pages[i] = pg;
		if (!PageDirty(pg) && (!PageUptodate(pg) || PageError(pg)))
			ClearPageError(pg);
		kmap(pg);
	}

	valid_size = ni->i_valid;

	if (frame_vbo >= valid_size || !clst_data) {
		for (i = 0; i < pages_per_frame; i++) {
			pg = pages[i];
			if (!pg || PageDirty(pg) ||
			    (PageUptodate(pg) && !PageError(pg)))
				continue;

			memset(page_address(pg), 0, PAGE_SIZE);
			flush_dcache_page(pg);
			SetPageUptodate(pg);
		}
		err = 0;
		goto out1;
	}

	unc_size = frame_vbo + frame_size > valid_size ?
			   (valid_size - frame_vbo) :
			   frame_size;

	/* read 'clst_data' clusters from disk */
	cmpr_size = clst_data << sbi->cluster_bits;
	frame_buf = ntfs_alloc(cmpr_size, 0);
	if (!frame_buf) {
		err = -ENOMEM;
		goto out1;
	}

	err = ntfs_read_run_nb(sbi, &ni->file.run, frame_vbo, frame_buf,
			       cmpr_size, NULL);
	if (err)
		goto out2;

	spin_lock(&sbi->compress.lock);
	frame_unc = sbi->compress.frame_unc;

	if (!is_compr) {
		unc_size_fin = unc_size;
		frame_unc = frame_buf;
	} else {
		/* decompress: frame_buf -> frame_unc */
		unc_size_fin = decompress_lznt(frame_buf, cmpr_size, frame_unc,
					       frame_size);
		if ((ssize_t)unc_size_fin < 0) {
			err = unc_size_fin;
			goto out3;
		}

		if (!unc_size_fin || unc_size_fin > frame_size) {
			err = -EINVAL;
			goto out3;
		}
	}

	for (i = 0; i < pages_per_frame; i++) {
		u8 *pa;
		u32 use, done;
		loff_t vbo;

		pg = pages[i];
		if (!pg)
			continue;

		if (PageDirty(pg) || (PageUptodate(pg) && !PageError(pg)))
			continue;

		pa = page_address(pg);

		use = 0;
		done = i * PAGE_SIZE;
		vbo = frame_vbo + done;

		if (vbo < valid_size && unc_size_fin > done) {
			use = unc_size_fin - done;
			if (use > PAGE_SIZE)
				use = PAGE_SIZE;
			if (vbo + use > valid_size)
				use = valid_size - vbo;
			memcpy(pa, frame_unc + done, use);
		}

		if (use < PAGE_SIZE)
			memset(pa + use, 0, PAGE_SIZE - use);

		flush_dcache_page(pg);
		SetPageUptodate(pg);
	}

out3:
	spin_unlock(&sbi->compress.lock);

out2:
	ntfs_free(frame_buf);
out1:
	for (i = 0; i < pages_per_frame; i++) {
		pg = pages[i];
		if (i == idx || !pg)
			continue;
		kunmap(pg);
		unlock_page(pg);
		put_page(pg);
	}

	if (err)
		SetPageError(page);
	kunmap(page);

out:
	/* At this point, err contains 0 or -EIO depending on the "critical" page */
	ntfs_free(pages);
	unlock_page(page);

	ntfs_free(ctx);

	return err;
}

/*
 * ni_writepage_cmpr
 *
 * helper for ntfs_writepage_cmpr
 */
int ni_writepage_cmpr(struct page *page, int sync)
{
	int err;
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	loff_t i_size = i_size_read(inode);
	struct ntfs_inode *ni = ntfs_i(inode);
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	pgoff_t index = page->index, end_index;
	u64 vbo = (u64)index << PAGE_SHIFT;
	u32 pages_per_frame = 0;
	struct page **pages = NULL;
	char *frame_buf = NULL;
	struct ATTR_LIST_ENTRY *le;
	struct ATTRIB *attr;
	u8 frame_bits;
	u32 frame_size, i, idx, unc_size;
	CLST frame;
	struct page *pg;
	char *frame_unc;
	u64 frame_vbo;
	size_t cmpr_size_fin, cmpr_size_clst;
	gfp_t mask;

	end_index = (i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	if (index >= end_index) {
		SetPageUptodate(page);
		err = 0;
		goto out;
	}

	le = NULL;
	attr = ni_find_attr(ni, NULL, &le, ATTR_DATA, NULL, 0, NULL, NULL);
	if (!attr) {
		err = -ENOENT;
		goto out;
	}

	if (!attr->non_res) {
		WARN_ON(1);
		err = 0;
		goto out;
	}

	if (!is_attr_compressed(attr)) {
		WARN_ON(1);
		err = -EINVAL;
		goto out;
	}

	if (sbi->cluster_size > NTFS_LZNT_MAX_CLUSTER) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (attr->nres.c_unit != NTFS_LZNT_CUNIT) {
		err = -EOPNOTSUPP;
		goto out;
	}

	frame_bits = NTFS_LZNT_CUNIT + sbi->cluster_bits;
	frame_size = sbi->cluster_size << NTFS_LZNT_CUNIT;
	frame = vbo >> frame_bits;
	frame_vbo = (u64)frame << frame_bits;
	unc_size = frame_vbo + frame_size > i_size ? (i_size - frame_vbo) :
						     frame_size;

	frame_buf = ntfs_alloc(frame_size, 0);
	if (!frame_buf) {
		err = -ENOMEM;
		goto out;
	}

	pages_per_frame = frame_size >> PAGE_SHIFT;
	pages = ntfs_alloc(pages_per_frame * sizeof(*pages), 1);
	if (!pages) {
		err = -ENOMEM;
		goto out;
	}

	idx = (vbo - frame_vbo) >> PAGE_SHIFT;
	pages[idx] = page;
	index = frame_vbo >> PAGE_SHIFT;
	mask = mapping_gfp_mask(mapping);
	kmap(page);

	for (i = 0; i < pages_per_frame && index < end_index; i++, index++) {
		if (i == idx)
			continue;

		// added FGP_CREAT
		pg = pagecache_get_page(
			mapping, index,
			FGP_LOCK | FGP_NOFS | FGP_CREAT | FGP_NOWAIT, mask);
		if (!pg)
			continue;

		pages[i] = pg;

		if (PageError(pg)) {
			err = -EIO;
			goto out2;
		}

		if (!PageDirty(pg) && !PageUptodate(pg)) {
			memset(page_address(pg), 0, PAGE_SIZE);
			flush_dcache_page(pg);
			SetPageUptodate(pg);
		}

		kmap(pg);
	}

	spin_lock(&sbi->compress.lock);
	frame_unc = sbi->compress.frame_unc;

	for (i = 0; i < pages_per_frame; i++) {
		pg = pages[i];
		if (pg)
			memcpy(frame_unc + i * PAGE_SIZE, page_address(pg),
			       PAGE_SIZE);
		else
			memset(frame_unc + i * PAGE_SIZE, 0, PAGE_SIZE);
	}

	/* compress: frame_unc -> frame_buf */
	cmpr_size_fin = compress_lznt(frame_unc, unc_size, frame_buf,
				      frame_size, sbi->compress.ctx);

	cmpr_size_clst = ntfs_up_cluster(sbi, cmpr_size_fin);
	if (cmpr_size_clst + sbi->cluster_size > frame_size) {
		/* write frame as is */
		memcpy(frame_buf, frame_unc, frame_size);
		cmpr_size_fin = frame_size;
	} else if (cmpr_size_fin) {
		memset(frame_buf + cmpr_size_fin, 0,
		       cmpr_size_clst - cmpr_size_fin);
	}
	spin_unlock(&sbi->compress.lock);

	err = attr_allocate_frame(ni, frame, cmpr_size_fin, ni->i_valid);
	if (err)
		goto out2;

	if (!cmpr_size_clst)
		goto out2;

	err = ntfs_sb_write_run(sbi, &ni->file.run, frame_vbo, frame_buf,
				cmpr_size_clst);
	if (err)
		goto out2;

out2:
	ntfs_free(frame_buf);
	for (i = 0; i < pages_per_frame; i++) {
		pg = pages[i];
		if (!pg || i == idx)
			continue;
		kunmap(pg);
		SetPageUptodate(pg);
		/* clear page dirty so that writepages wouldn't work for us. */
		ClearPageDirty(pg);
		unlock_page(pg);
		put_page(pg);
	}

	if (err)
		SetPageError(page);
	kunmap(page);

out:
	/* At this point, err contains 0 or -EIO depending on the "critical" page */
	ntfs_free(pages);
	set_page_writeback(page);
	unlock_page(page);
	end_page_writeback(page);

	return err;
}

/*
 * update duplicate info of ATTR_FILE_NAME in MFT and in parent directories
 */
static bool ni_update_parent(struct ntfs_inode *ni, struct NTFS_DUP_INFO *dup,
			     int sync)
{
	struct ATTRIB *attr;
	struct mft_inode *mi;
	struct ATTR_LIST_ENTRY *le = NULL;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct super_block *sb = sbi->sb;
	bool re_dirty = false;
	bool active = sb->s_flags & SB_ACTIVE;
	bool upd_parent = ni->ni_flags & NI_FLAG_UPDATE_PARENT;

	if (ni->mi.mrec->flags & RECORD_FLAG_DIR) {
		dup->fa |= FILE_ATTRIBUTE_DIRECTORY;
		attr = NULL;
		dup->alloc_size = 0;
		dup->data_size = 0;
	} else {
		dup->fa &= ~FILE_ATTRIBUTE_DIRECTORY;

		attr = ni_find_attr(ni, NULL, &le, ATTR_DATA, NULL, 0, NULL,
				    &mi);
		if (!attr) {
			dup->alloc_size = dup->data_size = 0;
		} else if (!attr->non_res) {
			u32 data_size = le32_to_cpu(attr->res.data_size);

			dup->alloc_size = cpu_to_le64(QuadAlign(data_size));
			dup->data_size = cpu_to_le64(data_size);
		} else {
			u64 new_valid = ni->i_valid;
			u64 data_size = le64_to_cpu(attr->nres.data_size);
			__le64 valid_le;

			dup->alloc_size = is_attr_ext(attr) ?
						  attr->nres.total_size :
						  attr->nres.alloc_size;
			dup->data_size = attr->nres.data_size;

			if (new_valid > data_size)
				new_valid = data_size;

			valid_le = cpu_to_le64(new_valid);
			if (valid_le != attr->nres.valid_size) {
				attr->nres.valid_size = valid_le;
				mi->dirty = true;
			}
		}
	}

	/* TODO: fill reparse info */
	dup->reparse = 0;
	dup->ea_size = 0;

	if (ni->ni_flags & NI_FLAG_EA) {
		attr = ni_find_attr(ni, attr, &le, ATTR_EA_INFO, NULL, 0, NULL,
				    NULL);
		if (attr) {
			const struct EA_INFO *info;

			info = resident_data_ex(attr, sizeof(struct EA_INFO));

			dup->ea_size = info->size_pack;
		}
	}

	attr = NULL;
	le = NULL;

	while ((attr = ni_find_attr(ni, attr, &le, ATTR_NAME, NULL, 0, NULL,
				    &mi))) {
		struct inode *dir;
		struct ATTR_FILE_NAME *fname;

		fname = resident_data_ex(attr, SIZEOF_ATTRIBUTE_FILENAME);
		if (!fname)
			continue;

		if (memcmp(&fname->dup, dup, sizeof(fname->dup))) {
			memcpy(&fname->dup, dup, sizeof(fname->dup));
			mi->dirty = true;
		} else if (!upd_parent) {
			continue;
		}

		if (!active)
			continue; /*avoid __wait_on_freeing_inode(inode); */

		/*ntfs_iget5 may sleep*/
		dir = ntfs_iget5(sb, &fname->home, NULL);
		if (IS_ERR(dir)) {
			ntfs_inode_warn(
				&ni->vfs_inode,
				"failed to open parent directory r=%lx to update",
				(long)ino_get(&fname->home));
			continue;
		}

		if (!is_bad_inode(dir)) {
			struct ntfs_inode *dir_ni = ntfs_i(dir);

			if (!ni_trylock(dir_ni)) {
				re_dirty = true;
			} else {
				indx_update_dup(dir_ni, sbi, fname, dup, sync);
				ni_unlock(dir_ni);
			}
		}
		iput(dir);
	}

	return re_dirty;
}

/*
 * ni_write_inode
 *
 * write mft base record and all subrecords to disk
 */
int ni_write_inode(struct inode *inode, int sync, const char *hint)
{
	int err = 0, err2;
	struct ntfs_inode *ni = ntfs_i(inode);
	struct super_block *sb = inode->i_sb;
	struct ntfs_sb_info *sbi = sb->s_fs_info;
	bool re_dirty = false;
	struct ATTR_STD_INFO *std;
	struct rb_node *node, *next;
	struct NTFS_DUP_INFO dup;

	if (is_bad_inode(inode))
		return 0;

	if (!ni_trylock(ni)) {
		/* 'ni' is under modification, skip for now */
		mark_inode_dirty_sync(inode);
		return 0;
	}

	if (is_rec_inuse(ni->mi.mrec) &&
	    !(sbi->flags & NTFS_FLAGS_LOG_REPLAYING) && inode->i_nlink) {
		bool modified = false;

		/* update times in standard attribute */
		std = ni_std(ni);
		if (!std) {
			err = -EINVAL;
			goto out;
		}

		/* Update the access times if they have changed. */
		dup.m_time = kernel2nt(&inode->i_mtime);
		if (std->m_time != dup.m_time) {
			std->m_time = dup.m_time;
			modified = true;
		}

		dup.c_time = kernel2nt(&inode->i_ctime);
		if (std->c_time != dup.c_time) {
			std->c_time = dup.c_time;
			modified = true;
		}

		dup.a_time = kernel2nt(&inode->i_atime);
		if (std->a_time != dup.a_time) {
			std->a_time = dup.a_time;
			modified = true;
		}

		dup.fa = ni->std_fa;
		if (std->fa != dup.fa) {
			std->fa = dup.fa;
			modified = true;
		}

		if (modified)
			ni->mi.dirty = true;

		if (!ntfs_is_meta_file(sbi, inode->i_ino) &&
		    (modified || ni->ni_flags & NI_FLAG_UPDATE_PARENT)) {
			dup.cr_time = std->cr_time;
			/* Not critical if this function fail */
			re_dirty = ni_update_parent(ni, &dup, sync);

			if (re_dirty)
				ni->ni_flags |= NI_FLAG_UPDATE_PARENT;
			else
				ni->ni_flags &= ~NI_FLAG_UPDATE_PARENT;
		}

		/* update attribute list */
		err = al_update(ni);
		if (err)
			goto out;
	}

	for (node = rb_first(&ni->mi_tree); node; node = next) {
		struct mft_inode *mi = rb_entry(node, struct mft_inode, node);
		bool is_empty;

		next = rb_next(node);

		if (!mi->dirty)
			continue;

		is_empty = !mi_enum_attr(mi, NULL);

		if (is_empty)
			clear_rec_inuse(mi->mrec);

		err2 = mi_write(mi, sync);
		if (!err && err2)
			err = err2;

		if (is_empty) {
			ntfs_mark_rec_free(sbi, mi->rno);
			rb_erase(node, &ni->mi_tree);
			mi_put(mi);
		}
	}

	err2 = mi_write(&ni->mi, sync);
	if (!err && err2)
		err = err2;
out:
	ni_unlock(ni);

	if (err) {
		ntfs_err(sb, "%s r=%lx failed, %d.", hint, inode->i_ino, err);
		ntfs_set_state(sbi, NTFS_DIRTY_ERROR);
		return err;
	}

	if (re_dirty && (sb->s_flags & SB_ACTIVE))
		mark_inode_dirty_sync(inode);

	if (inode->i_ino < sbi->mft.recs_mirr)
		sbi->flags |= NTFS_FLAGS_MFTMIRR;

	return 0;
}
