/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

#include "threads/vaddr.h"
#include "threads/mmu.h"


/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */

	/* initialize global frame table (for users) */
	int user_pages = get_user_pages_cnt(PAL_USER);
	ft = malloc(sizeof(struct frame) * user_pages);		// MALLOC! : ft
	ft_len = user_pages;
	ft_pointer = undertaker = 0;
	for (int i = 0 ; i < ft_len ; i++) {
		ft[i].kva = NULL;
		ft[i].page = NULL;
	}
	lock_init(&ft_lock);

	// printf("ft_len: %d\n", ft_len);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {

		/* TODO: Create the page, fetch the initializer according to the VM type, */
		page = malloc(sizeof(struct page));	// MALLOC! : page
		if (page == NULL)
			goto err;

		bool *initializer_for_type;
		if (VM_TYPE(type) == VM_ANON)
			initializer_for_type = anon_initializer;
		else if (VM_TYPE(type) == VM_FILE)
			initializer_for_type = file_backed_initializer;
		else
			goto err;

		/* TODO: and then create "uninit" page struct by calling uninit_new. */
		uninit_new(page, upage, init, type, aux, initializer_for_type);

		/* TODO: You should modify the field after calling the uninit_new. */
		page->writable = writable;

		/* TODO: Insert the page into the spt. */
		if (!spt_insert_page(spt, page))
			goto err;

		if (type & VM_STACK || type & VM_IMMEDIATE) {
			if (!vm_do_claim_page(page))
				goto err;
			if (type & VM_STACK)
				thread_current()->user_stack_bottom = upage;
		}

		return true;
	}
err:
	if (page != NULL)
		free(page);

	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	/* TODO: Fill this function. */
	struct page *page = NULL;
	struct list_elem *e;
	for (e = list_begin (&spt->sp_list); e != list_end (&spt->sp_list); e = list_next (e)) {
		struct page *p = list_entry(e, struct page, elem);
		if(p->va == pg_start_of(va)) {
			page = p;
			break;
		}
	}
	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	int succ = false;

	/* TODO: Fill this function. */
	list_push_front(&spt->sp_list, &page->elem);
	succ = true;

	return succ;
}

void
spt_print(struct supplemental_page_table *spt) {

	struct list *sp_list = &spt->sp_list;
	if (list_empty(sp_list))
		return;
		
	struct list_elem *e;
	int cnt = 1;

	printf("██ tid %d spt_print\n", thread_current()->tid);
	for (e = list_begin (sp_list); e != list_end (sp_list); e = list_next (e)) {
		struct page *p = list_entry(e, struct page, elem);
		printf("%3d | p->va : %-12p  |  p->frame : %-12p  |  p->writable : %d\n",
				cnt++, p->va, p->frame, p->writable);
	}
	printf("# USER_STACK_BOTTOM : %p\n", thread_current()->user_stack_bottom);
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	undertaker %= ft_len;

	 /* TODO: The policy for eviction is up to you. ▶ clock algorithm */
	while (pml4_is_accessed(ft[undertaker].pml4, ft[undertaker].page->va)) {
		// printf("%d | %d 's accessed 1 ➡ 0\n", ft_len, undertaker);
		pml4_set_accessed(ft[undertaker].pml4, ft[undertaker++].page->va, false);	// set accessed bit to 0 and move on.
		undertaker %= ft_len;
	}

	// printf("💥 %d 's accessed : 0\n", undertaker);
	return &ft[undertaker++];
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	printf("❗ eviction occured");
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	if (!swap_out(victim->page))	// include clearing dirty bit and present bit.
		return NULL;
	
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;

	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER | PAL_ZERO);	// MALLOC! : physical page

	if (kva == NULL) {	// run out of memory	
		// /* !!! for debug !!! */
		// for (int idx = 0; idx < ft_len; idx++) {
		// 	frame = &ft[idx];
		// 	if (frame->kva == NULL)
		// 		PANIC("frame table has been not updated properly.");
		// }
		// /* !!! for debug !!! */
		/* eviction */
		frame = vm_evict_frame();
		kva = frame->kva;
	}
	else {	// update frame table (eviction does not need this)
		for (int i = 0; i < ft_len; i++) {
			frame = &ft[ft_pointer++];
			if (frame->kva == NULL) { 
				ft_pointer %= ft_len;
				break;
			}
			ft_pointer %= ft_len;
		}
	}
	ASSERT (frame != NULL);

	frame->kva = kva;
	frame->page = NULL;
	frame->pml4 = thread_current()->pml4;	// store pml4 of this thread, which is getting this frame.
	
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	void *user_stack_bottom = thread_current()->user_stack_bottom;
	int page_cnt = (user_stack_bottom - pg_round_down(addr)) / PGSIZE;

	while (page_cnt-- > 0) {
		user_stack_bottom -= PGSIZE;

		if (!vm_alloc_page(VM_ANON | VM_STACK, user_stack_bottom, true))
			PANIC("vm_stack_growth : failed");
	}

}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {

	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	void *rsp = thread_current()->rsp;
	void *user_stack_bottom = thread_current()->user_stack_bottom;
	void *fault_addr = addr;

	/* TODO: Validate the fault 
	 * Any invalid access terminates the process and thereby frees all of its resources.*/
	if (!not_present)			// already present.
		return false;
	if (is_kernel_vaddr(addr))	// kernel address is not lazily loaded. something else is wrong. (including user try to access kernel)
		return false;

	page = spt_find_page(spt, addr);	// find page in spt.

	if (page == NULL) {			
		/* check if stack-growth case. */

		if (rsp != NULL	// not NULL if reaches here from user page-fault or kernel page-fault during syscall handling.
			&& (USER_STACK_LIMIT <= fault_addr && fault_addr < user_stack_bottom)
			&& ((void *)(rsp - 8) == fault_addr || fault_addr >= rsp))
		{
			vm_stack_growth(fault_addr);
			return true;
		}

		return false;	// should not be expected to read or write any data at the address.
	}
	
	if (write && page->writable == 0)
		return false;			// cannot write on read-only page.

	/* Here we can say that fault was a valid demand for page. */
	return vm_do_claim_page (page);
	
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);	// FREE! : page
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	PANIC ("todo : vm_claim_page");

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct thread *t = thread_current();
	lock_acquire(&ft_lock);
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;
	lock_release(&ft_lock);

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	ASSERT(pml4_get_page (t->pml4, page->va) == NULL);
	if(!pml4_set_page (t->pml4, page->va, frame->kva, page->writable))
		return false;

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	list_init(&spt->sp_list);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	// this function is called from do_fork() routine of child process.
	// parent process waits until the child completes duplication.
	struct list *src_list = &src->sp_list;
	struct list *dst_list = &dst->sp_list;

	struct list_elem *e;
	for (e = list_begin (src_list); e != list_end (src_list); e = list_next (e)) {
		struct page *src_page = list_entry(e, struct page, elem);
		struct page *dst_page = NULL;
		enum vm_type operation_type = VM_TYPE(src_page->operations->type);

		enum vm_type type 		= page_get_type(src_page);
		void *va 				= src_page->va;
		bool writable 			= src_page->writable;

		if (operation_type == VM_UNINIT)
		{
			if (type == VM_FILE) {
				/* file backed pages (mappings) are not inherited */
			}
			else {
				/* Fetch vm_initializer (not page_initializer) */
				vm_initializer *init = src_page->uninit.init;
				/* Duplicate args */
				uint64_t *la = src_page->uninit.aux;
				void *new_la = malloc(sizeof(struct lazy_args));	// MALLOC! : lazy_args
				memcpy(new_la, la, sizeof(struct lazy_args));

				/* alloc */
				if (!vm_alloc_page_with_initializer(type, va, writable, init, new_la))
					return false;
			}
		}
		else if (operation_type == VM_ANON)
		{
			/* alloc and claim (with VM_IMMEDIATE)*/
			if(!vm_alloc_page(type | VM_IMMEDIATE, va, writable))
				return false;
			
			dst_page = spt_find_page(dst_list, va);
			ASSERT(dst_page != NULL);

			/* memcpy */
			memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
		}
		else if (operation_type == VM_FILE)
		{
			/* file backed pages (mappings) are not inherited */
		}
		else
			NOT_REACHED();
	}

	// spt_print(dst_list);
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

	while (!list_empty (&spt->sp_list)) {
		struct list_elem *e = list_front(&spt->sp_list);
		struct page *page = list_entry(e, struct page, elem);

		if (page->operations->type == VM_FILE) {
			do_munmap(page->file.root_addr);
		}
		else if (page->operations->type == VM_UNINIT
				&& VM_TYPE(page->uninit.type) == VM_FILE)
		{
			struct lazy_args *la = page->uninit.aux;
			do_munmap(la->root_addr);
		}
		else {
			list_remove(e);
			vm_dealloc_page(page);	// destroy and free page.
		}
	}
	spt_print(spt);
}
