/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool							// bit flag stored here. ↘
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	struct lazy_args *la = page->uninit.aux;

	file_page->mapped_file = la->file;
	file_page->valid_bytes = la->page_read_bytes;
	file_page->file_offset = la->ofs;
	file_page->root_addr = la->root_addr;

	return true;
}

/* Swap in the page by read contents from the file. */
/* pml4_set_page() already done by caller*/
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	struct lazy_args *la = malloc(sizeof(struct lazy_args));

	la->file 			= file_page->mapped_file;
	la->page_read_bytes = file_page->valid_bytes;
	la->page_zero_bytes = PGSIZE - file_page->valid_bytes;
	la->ofs 			= file_page->file_offset;
	la->root_addr 		= file_page->root_addr;

	return do_lazy_load(page, la);
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page = &page->file;
	struct file *mapped_file = file_page->mapped_file;
	void *pml4 = page->frame->pml4;

	if (pml4_is_dirty(pml4, page->va)) {	// check if the page is modified by process.
		size_t valid_bytes = file_page->valid_bytes;
		off_t file_offset = file_page->file_offset;
		
		if (valid_bytes != 0) {
			/* write back */
			bool lock_acquired_here = false;
			lock_acquire_safe(&filesys_lock, &lock_acquired_here);
			if (valid_bytes != file_write_at(mapped_file, page->va, valid_bytes, file_offset)) {
				printf("file_backed_swap_out : file write fail");
				lock_release_safe(&filesys_lock, lock_acquired_here);
				return false;
			}

			lock_release_safe(&filesys_lock, lock_acquired_here);
		}
	}
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page = &page->file;


	if (pml4_get_page(thread_current()->pml4, page->va) != NULL) {
	/* first things first, swap out. */
		file_backed_swap_out(page);

		pml4_set_dirty(thread_current()->pml4, page->va, false);	// clean dirty bit.
		pml4_clear_page(thread_current()->pml4, page->va);		// set PTE is not present.

	/* clean up struct frame in ft, which was mapped to this page. */
	// TODO : palloc free kva
		palloc_free_page(page->frame->kva);
		page->frame->kva = NULL;
		page->frame->page = NULL;

	// help ft_pointer to find empty struct frame easily.
		ft_pointer = page->frame - ft;		// pointer arithmetic
	}

}

/* 
 * mmap and munmap
 */
static bool populate_pages (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable);

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
	ASSERT(pg_ofs(addr) == 0);

	struct file *new_file = file_reopen(file);	// MALLOC! : file
	if (file == NULL)
		return NULL;
	size_t file_size 	= file_length(file);
	size_t max_read 	= file_size - offset;

	size_t read_bytes 	= length <= max_read ? length : max_read;
	size_t zero_bytes 	= pg_round_up(length) - read_bytes;

	if (!populate_pages (new_file, offset, addr, read_bytes, zero_bytes, writable))
		return NULL;
	
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct list *sp_list = &thread_current()->spt.sp_list;
	struct file *mmaped_file = NULL;
	
	// spt_print(&thread_current()->spt);
	bool lock_acquired_here = false;
	lock_acquire_safe(&swap_lock, &lock_acquired_here);
	struct list_elem *e = list_begin(sp_list);
	while (e != list_end (sp_list)) {
		struct page *page = list_entry(e, struct page, elem);
		enum vm_type type = VM_TYPE(page->operations->type);

		if (type == VM_FILE) {
			if (page->file.root_addr == addr) {
				struct list_elem *next_e = list_remove(e);
				mmaped_file = page->file.mapped_file;
				
				vm_dealloc_page(page);

				e = next_e;
				continue;
			}
		}
		else if (type == VM_UNINIT) {
			struct lazy_args *la = page->uninit.aux;
			if (la->root_addr == addr) {
				struct list_elem *next_e = list_remove(e);
				mmaped_file = la->file;

				vm_dealloc_page(page);

				e = next_e;
				continue;
			}
		}

		/* not related pages */
		e = list_next(e);
	}
	lock_release_safe(&swap_lock, lock_acquired_here);

	ASSERT(mmaped_file != NULL);

	/* close mapped file */
	bool lock_acquired_in_here = false;
	lock_acquire_safe(&filesys_lock, &lock_acquired_in_here);
	file_close(mmaped_file);		// FREE! : file
	lock_release_safe(&filesys_lock, lock_acquired_in_here);
}

static bool
populate_pages (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);

	void *root_addr = upage;

	while (read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		// MALLOC! : lazy_args
		struct lazy_args *lazy_args = malloc(sizeof(struct lazy_args));
		if (lazy_args == NULL)
			return false;
		lazy_args->file = file;
		lazy_args->ofs = ofs;
		lazy_args->page_read_bytes = page_read_bytes;
		lazy_args->page_zero_bytes = page_zero_bytes;
		lazy_args->root_addr = root_addr;

		if (!vm_alloc_page_with_initializer (VM_FILE, upage,
					writable, do_lazy_load, lazy_args))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;
	}
	return true;
}