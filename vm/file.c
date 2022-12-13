/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "userprog/process.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in(struct page *page, void *kva)
{
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset)
{
	struct file *m_file = file_reopen(file);
	void *m_addr = addr;
	size_t read_byte = length > file_length(file) ? file_length(file) : length;
	size_t zero_byte = PGSIZE - read_byte % PGSIZE;

	while (read_byte > 0 || zero_byte > 0)
	{
		size_t page_read_byte = read_byte < PGSIZE ? PGSIZE : read_byte;
		size_t page_zero_byte = PGSIZE - read_byte;

		struct lazy_args *m_la = (struct lazy_args *)malloc(sizeof(struct lazy_args));
		m_la->file = m_file;
		m_la->ofs = offset;
		m_la->page_read_bytes = page_read_byte;
		m_la->page_zero_bytes = page_zero_byte;
		m_la->writable = writable;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, m_la))
			return NULL;

		read_byte -= page_read_byte;
		zero_byte -= page_zero_byte;
		addr += PGSIZE;
		offset += page_read_byte;
	}

	return m_addr;
}
/* Do the munmap */
void do_munmap(void *addr)
{
	while (1)
	{
		struct thread *curr = thread_current();
		struct page *page = spt_find_page(&curr->spt, addr);

		if (!page)
			break;

		struct lazy_args *lazy_args = (struct lazy_args *)page->uninit.aux;

		if (pml4_is_dirty(curr->pml4, addr))
		{
			file_write_at(lazy_args->file, addr, lazy_args->page_read_bytes, lazy_args->ofs);
			pml4_set_dirty(curr->pml4, addr, 0);
		}
		pml4_clear_page(curr->pml4, page->va);
		addr += PGSIZE;
	}
}
