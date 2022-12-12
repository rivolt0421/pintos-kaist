/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "lib/string.h"
#include "userprog/process.h"
#include "include/lib/kernel/hash.h"

struct list *ft;
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
	list_init(&ft);
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
		bool *initializer_for_type = NULL;

		if (VM_TYPE(type) == VM_ANON)
			initializer_for_type = anon_initializer;
		else if (VM_TYPE(type) == VM_FILE)
			initializer_for_type = file_backed_initializer;
		else
			goto err;

		/* TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		uninit_new(page, upage, init, type, aux, initializer_for_type);

		page->writable = writable;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt, void *va)
{
	/* TODO: Fill this function. */
	struct page *find_page = malloc(sizeof(struct page));
	struct hash_elem *e;

	find_page->va = pg_round_down(va);
	e = hash_find(&spt->pages, &find_page->hash_elem);
	free(find_page);
	if (e)
		return hash_entry(e, struct page, hash_elem);
	return NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	/* TODO: Fill this function. */
	return insert_page(&spt->pages, page);
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
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */
	PANIC("todo : eviction");
	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = malloc(sizeof(struct frame));

	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER | PAL_ZERO); // MALLOC!:frame
	if (kva == NULL)
	{
		frame = vm_evict_frame();
		frame->kva = kva;
		frame->page = NULL;
	}

	/* update frame table */
	ASSERT(frame != NULL);

	list_push_back(&ft, &frame->f_elem);
	frame->kva = kva;
	frame->page = NULL;

	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
	if (vm_alloc_page(VM_ANON | VM_STACK, addr, true))
	{
		vm_claim_page(addr);
		thread_current()->stack_bottom -= PGSIZE;
	}
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
	if (is_kernel_vaddr(addr)) // user try to access kernel address.
		return false;

	void *rsp_stack =
		is_kernel_vaddr(f->rsp) ? thread_current()->rsp_stack : f->rsp;
	if (not_present)
	{
		if (!vm_claim_page(addr))
		{
			if (rsp_stack - 8 <= addr && USER_STACK - 0x100000 <= addr &&
				addr <= USER_STACK)
			{
				vm_stack_growth(thread_current()->stack_bottom - PGSIZE);
				return true;
			}
			return false;
		}
		else
			return true;
	}
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page); // FREE!:page
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va)
{
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);

	if (page == NULL)
		return false;

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
	if (install_page(page->va, frame->kva, page->writable))
		return swap_in(page, frame->kva);

	return false;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->pages, page_hash, page_cmp_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
								  struct supplemental_page_table *src UNUSED)
{
	/*src부터 dst까지 supplemental page table를 복사하세요.
	이것은 자식이 부모의 실행 context를 상속할 필요가 있을 때 사용됩니다.(예 - fork()).
	src의 supplemental page table를 반복하면서 dst의 supplemental page table의 엔트리의 정확한 복사본을 만드세요.
	당신은 초기화되지않은(uninit) 페이지를 할당하고 그것들을 바로 요청할 필요가 있을 것입니다.*/

	struct hash_iterator i;

	hash_first(&i, &src->pages);
	while (hash_next(&i))
	{
		struct page *parent_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type p_type = page_get_type(parent_page);
		void *p_upage = parent_page->va;
		bool p_writable = parent_page->writable;
		vm_initializer *p_init = parent_page->uninit.init;

		struct lazy_args *parent_args = (struct lazy_args *)parent_page->uninit.aux;
		struct lazy_args *child_args = (struct lazy_args *)malloc(sizeof(struct lazy_args));

		if (child_args == NULL)
			return false;
		if (parent_args != NULL)
		{
			child_args->file = parent_args->file;
			child_args->ofs = parent_args->ofs;
			child_args->page_read_bytes = parent_args->page_read_bytes;
			child_args->page_zero_bytes = parent_args->page_zero_bytes;
		}

		if (parent_page->uninit.type & VM_STACK)
		{
			setup_stack(&thread_current()->tf);
		}
		else if (parent_page->operations->type == VM_UNINIT)
		{
			if (!vm_alloc_page_with_initializer(p_type, p_upage, p_writable, p_init,
												(void *)child_args))
				return false;
		}
		else
		{
			if (!vm_alloc_page(p_type, p_upage, p_writable))
				return false;
			if (!vm_claim_page(p_upage))
				return false;
		}

		if (parent_page->operations->type != VM_UNINIT)
		{
			struct page *child_page = spt_find_page(dst, p_upage);
			if (child_page == NULL)
				return false;
			memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
		}
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	// hash_destroy(&spt->pages, spt_des);
	hash_clear(&spt->pages, spt_des);
}

unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof(p->va));
}

bool page_cmp_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);

	return a->va < b->va;
}

bool insert_page(struct hash *pages, struct page *p)
{
	if (hash_insert(pages, &p->hash_elem) == NULL)
	{
		return true;
	}
	else
		return false;
}

bool delete_page(struct hash *pages, struct page *p)
{
	if (!hash_delete(pages, &p->hash_elem))
		return true;
	else
		return false;
}

void spt_des(struct hash_elem *e, void *aux)
{
	const struct page *p = hash_entry(e, struct page, hash_elem);
	free(p);
}
