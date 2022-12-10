/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "lib/string.h"
#include "userprog/process.h"

struct lock ft_lock;

struct frame *ft;
int ft_len;
int ft_pointer;
int undertaker;
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */

	/* initialize global frame table (for users) */
	int user_pages = get_user_pages_cnt(PAL_USER);
	ft = malloc(sizeof(struct frame) * user_pages); // MALLOC!:ft
	ft_len = user_pages;
	ft_pointer = undertaker = 0;
	for (int i = 0; i < ft_len; i++)
	{
		ft[i].kva = NULL;
		ft[i].page = NULL;
	}
	lock_init(&ft_lock);

	printf("ft_len: %d\n", ft_len);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	// ASSERT(VM_TYPE(type) != VM_UNINIT)
	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initializer according to the VM type, */
		struct page *page = malloc(sizeof(struct page)); // MALLOC!:page
		if (page == NULL)
			goto err;
		bool *initializer_for_type;
		if (VM_TYPE(type) == VM_ANON)
			initializer_for_type = anon_initializer;
		else if (VM_TYPE(type) == VM_FILE)
			initializer_for_type = file_backed_initializer;

		// else if (VM_TYPE(type) == VM_PAGE_CACHE)
		// 	initializer_for_type = page_cache_initializer;
		else
			goto err;
		/* TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		uninit_new(page, upage, init, type, aux, initializer_for_type);
		page->writable = writable;

		/* TODO: Insert the page into the spt. */
		if (!spt_insert_page(spt, page))
			goto err;

		if (type & VM_STACK)
			return vm_do_claim_page(page);
		return true;
	}
	else
		goto err;
err:

	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt, void *va)
{
	/* TODO: Fill this function. */
	struct page *page = NULL;
	struct list *list = &spt->sp_list;
	struct list_elem *e;
	uint64_t down_va;

	down_va = pg_round_down(va);
	e = list_begin(list);

	if (list_empty(list) || e == NULL)
	{
		return NULL;
	}

	while (e != list_end(list))
	{
		struct page *p = list_entry(e, struct page, elem);
		if (p->va == down_va)
		{
			return p;
		}
		e = list_next(e);
	}

	// for (e = list_begin(&spt->sp_list); e != list_end(&spt->sp_list); e = list_next(e))
	// {
	// 	struct page *p = list_entry(e, struct page, elem);
	// 	if (p->va == va)
	// 	{
	// 		return p;
	// 		// page = p;
	// 		// break;
	// 	}
	// }
	return NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	int succ = false;

	if (page == NULL)
		return succ;
	/* TODO: Fill this function. */
	list_push_front(&spt->sp_list, &page->elem);
	succ = true;

	return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	struct thread *curr = thread_current();
	/* TODO: The policy for eviction is up to you. */
	//
	for (int i = 0; i < ft_len; i++)
	{
		if (pml4_is_accessed(curr->pml4, ft[ft_pointer].kva))
		{
			victim = &ft[ft_pointer];
			break;
		}
		ft_pointer++;
		ft_pointer %= ft_len;
		;
		return victim;
	}
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = NULL;

	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER | PAL_ZERO); // MALLOC!:frame
	if (kva == NULL)
		PANIC("todo : eviction");

	/* update frame table */
	lock_acquire(&ft_lock);

	for (int i = 0; i < ft_len; i++)
	{
		if (ft[ft_pointer].kva == NULL)
		{
			frame = &ft[ft_pointer];
			ft_pointer++;
			ft_pointer %= ft_len;

			break;
		}
		ft_pointer++;
		ft_pointer %= ft_len;
	}
	ASSERT(frame != NULL); // should exist empty frame struct in ft if palloc returned valid pointer.
	frame->kva = kva;
	frame->page = NULL;

	lock_release(&ft_lock);

	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr,
						 bool user, bool write, bool not_present)
{
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = NULL;

	/* TODO: Validate the fault
	 * Any invalid access terminates the process and thereby frees all of its resources.*/
	// if (!not_present || !user) // already present. or kernel fault.
	// 	return false;
	// if (!not_present) // already present.
	// 	return false;
	if (is_kernel_vaddr(addr)) // user try to access kernel address.
		return false;

	page = spt_find_page(spt, addr);
	if (page == NULL) // user should not expect any data at the address. (== cannot find page from spt list)
		return false;
	// if (write)
	// {
	// 	struct lazy_args *lazy_args = page->uninit.aux;
	// 	if (!lazy_args->writable)
	// 		return false; // user try to write read-only page.
	// }

	/* TODO: Your code goes here */

	return vm_do_claim_page(page); // claim new page to kernel
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page); // FREE!:page
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	// page->va = va;
	// PANIC("todo : vm_claim_page");
	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();
	struct thread *t = thread_current();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	ASSERT(pml4_get_page(t->pml4, page->va) == NULL);
	if (!pml4_set_page(t->pml4, page->va, frame->kva, true))
		return false;
	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	list_init(&spt->sp_list);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
								  struct supplemental_page_table *src UNUSED)
{
	/*src부터 dst까지 supplemental page table를 복사하세요.
	이것은 자식이 부모의 실행 context를 상속할 필요가 있을 때 사용됩니다.(예 - fork()).
	src의 supplemental page table를 반복하면서 dst의 supplemental page table의 엔트리의 정확한 복사본을 만드세요.
	당신은 초기화되지않은(uninit) 페이지를 할당하고 그것들을 바로 요청할 필요가 있을 것입니다.*/
	// list_init(&dst->sp_list);

	struct list_elem *e;
	if (list_empty(&src->sp_list))
	{
		return false;
	}

	e = list_begin(&src->sp_list);

	while (e != list_end(&src->sp_list))
	{

		enum vm_type p_type;
		void *p_upage;
		bool p_writable;
		vm_initializer *p_init;
		struct file *p_file;

		struct page *old_page = list_entry(e, struct page, elem);
		struct lazy_args *old_la = old_page->uninit.aux;
		p_type = old_page->operations->type;
		p_upage = old_page->va;
		p_writable = old_page->writable;
		p_init = old_page->uninit.init;

		/* Stack page is special. */
		struct page *new_page = NULL;
		struct lazy_args *new_la = (struct lazy_args *)malloc(sizeof(struct lazy_args));

		// if ((old_page->uninit.type & VM_STACK) == 0)
		if (old_la != NULL)
		{
			new_la->file = old_la->file;
			new_la->ofs = old_la->ofs;
			new_la->page_read_bytes = old_la->page_read_bytes;
			new_la->page_zero_bytes = old_la->page_zero_bytes;
		}
		if ((old_page->uninit.type & VM_STACK) == 0)
		{
			setup_stack(&thread_current()->tf);
		}

		switch (p_type)
		{
		case (VM_UNINIT):
			if (!vm_alloc_page_with_initializer(p_type, p_upage, p_writable, p_init, new_la))
				return false;
		case (VM_ANON):
			if (!vm_alloc_page(p_type, p_upage, p_writable))
				return false;
			if (!vm_claim_page(p_upage))
				return false;
			struct page *new_page = spt_find_page(&thread_current()->spt, p_upage);
			if (new_page != NULL)
				memcpy(new_page->frame->kva, old_page->frame->kva, PGSIZE);
		}
		e = list_next(e);
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct list_elem *e;
	while (!list_empty(&spt->sp_list))
	{
		if (list_begin(&spt->sp_list) == NULL)
		{
			return;
		}
		struct list_elem *e = list_pop_front(&spt->sp_list);
		struct page *p = list_entry(e, struct page, elem);
		vm_dealloc_page(p);
	}
	list_init(&spt->sp_list);
}
