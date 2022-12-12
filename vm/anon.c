/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get (1, 1);	// 1:1 - swap
	size_t sector_cnt = disk_size(swap_disk);
	printf("██ swap_disk - sector count : %d\n", sector_cnt);

	swap_table = bitmap_create(sector_cnt);
	bitmap_set_all(swap_table, false);	// set all available

	lock_init(&swap_lock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */		 // VM_STACK은 ⬆ 여기 묻어있다.
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->sec_no = -1;
}

/* Swap in the page by read contents from the swap disk. */
/* pml4_set_page() already done by caller*/
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	disk_sector_t sec_no = anon_page->sec_no;
	ASSERT(sec_no != -1);

	void *slice = kva;
	for (int i = 0 ; i < 8 ; i++) {
		disk_read(swap_disk, sec_no + i, slice);
		slice += DISK_SECTOR_SIZE;
	}

	bool lock_acquired_here = false;
	lock_acquire_safe(&swap_lock, &lock_acquired_here);

	bitmap_set_multiple(swap_table, sec_no, 8, false);	// mark previously occupied 8 slots free.

	lock_release_safe(&swap_lock, lock_acquired_here);
	
	anon_page->sec_no = -1;
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	void *pml4 = page->frame->pml4;
	if (anon_page->sec_no != -1) {
		printf("DEBUG - anon_page->sec_no : %d\n", anon_page->sec_no);
		ASSERT(anon_page->sec_no == -1);
	}

	/* find empty swap slot */
	bool lock_acquired_here = false;
	lock_acquire_safe(&swap_lock, &lock_acquired_here);
									// 512 bytes (per sector) * 8 = 4096 bytes (one page)
	disk_sector_t sec_no = bitmap_scan_and_flip(swap_table, 0, 8, false);	// find consecutive 8 empty slots and mark(flip) them occupied(true).
	if (sec_no == BITMAP_ERROR)
		PANIC("The Notorious O.O.M.");
	anon_page->sec_no = sec_no;		// remember sec_no for swap in.

	lock_release_safe(&swap_lock, lock_acquired_here);

	void *slice = page->frame->kva;
	for (int i = 0 ; i < 8 ; i++) {
		disk_write(swap_disk, sec_no + i, slice);
		slice += DISK_SECTOR_SIZE;
	}

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	lock_acquire(&ft_lock);

	if (pml4_get_page(thread_current()->pml4, page->va) != NULL) {

		pml4_set_dirty(thread_current()->pml4, page->va, false);	// clean dirty bit.
		pml4_clear_page(thread_current()->pml4, page->va);		// set PTE is not present.

	/* clean up struct frame in ft, which was mapped to this page. */
	// TODO : palloc free kva
		palloc_free_page(page->frame->kva);
		page->frame->kva = NULL;
		page->frame->page = NULL;
	}

	// help ft_pointer to find empty struct frame easily.
	ft_pointer = page->frame - ft;		// pointer arithmetic

	lock_release(&ft_lock);
}
