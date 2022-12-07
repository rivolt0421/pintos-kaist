#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void **args);
static void __do_fork (void **);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
	/* initialize fd_table */
	intptr_t *fd_table = current->fd_table;
	char i = 0;
	while(i < FD_MAX) {	// 0 ~ FD_MAX (FD_MAX개)
		fd_table[i++] = 0;
	}
	current->fd_count = 2;	// 0 (STDIN_FILENO), 1 (STDOUT_FILENO)

	/* initialize for deny write on executables */
	current->running_executable = 0;  // NULL

	/* initialize parent-child relationship */
	current->sorry_mama = 0;  // NULL
	list_init(&current->child_list);

	/* initialize for stack growth */
	current->rsp = NULL;
	current->user_stack_bottom = USER_STACK;

}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy, *ptr;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* Create a new thread to execute FILE_NAME. */
	if((ptr = strchr((char *)file_name, ' '))) {
		*ptr = '\0';
	}

	struct semaphore first_userprog_started;
	sema_init(&first_userprog_started, 0);
	uintptr_t args[3] = { fn_copy, thread_current(), &first_userprog_started };

	tid = thread_create (file_name, PRI_DEFAULT, initd, args);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);

	if(ptr) {
		*ptr = ' ';
	}
	
	sema_down(&first_userprog_started);
	
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void **args) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	/* make parent-child relationship with initial_thread */
	struct thread *current = thread_current();
	char *f_name = args[0];
	struct thread *main_thread = args[1];
	struct semaphore *first_userprog_started = args[2];

	/* main_thread does not call process_init().
	 * Therefore, explicitly initialize child_list */
	list_init(&main_thread->child_list);

	struct child *child = malloc(sizeof(struct child));
	current->sorry_mama = child;

	child->self_thread = current;
	child->tid = current->tid;
	sema_init(&child->sema, 0);
	list_push_back(&main_thread->child_list, &child->elem);
	sema_up(first_userprog_started);

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	struct semaphore duplicate_done;
	uintptr_t args[3] = { thread_current(), if_, &duplicate_done };
	tid_t tid;
	
	sema_init(&duplicate_done, 0);
	tid = thread_create (name, PRI_DEFAULT, __do_fork, args);

	if (tid != TID_ERROR)
		/* Wait until child completes duplication. */
		sema_down (&duplicate_done);

	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kern_pte(pte))
		return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

/* Duplicate the parent's open files to current.
 * Some of members should not be duplicated here (i.e. pml4, tf ...).
 * Note : I'm not sure that this code should have wrapped by `#ifndef VM`. */
static bool
duplicate_open_files(struct thread *current, struct thread *parent) {

	/* Duplicate files in fd_table. */
	int i;
	for (i = 0; i < FD_MAX; i++) {
		if (parent->fd_table[i] == NULL)
			continue;
		current->fd_table[i] = file_duplicate(parent->fd_table[i]);
	}
	current->fd_count = parent->fd_count;

	/* Duplicate running_executable file */
	current->running_executable = file_duplicate(parent->running_executable);

}


/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void **aux) {
	struct intr_frame if_;	// for do_iret
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux[0];
	struct intr_frame *parent_if = (struct intr_frame *) aux[1];
	struct semaphore *duplicate_done = (struct semaphore *) aux[2];

	process_init();

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);

#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
	current->user_stack_bottom = parent->user_stack_bottom;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	
	/* 3. Duplicate thread. (with files) */
	lock_acquire(&filesys_lock);
	duplicate_open_files (current, parent);  //fd_table, running_executable
	lock_release(&filesys_lock);

	/* 4. set parent-child relationship */
	struct child *child = malloc(sizeof(struct child));
	current->sorry_mama = child;

	child->self_thread = thread_current();
	child->tid = thread_current()->tid;
	sema_init(&child->sema, 0);
	list_push_back(&parent->child_list, &child->elem);
	sema_up(duplicate_done);	// waking up parent
								// 자식이(현재 스레드가) 부모 스레드의 커널 스택에 있는 정보들을
								// 다 이용했기 때문에, 부모가 일어나서(wake up) fork handler 함수를
								// 반환해도 괜찮다는 의미.
	
	/* Finally, switch to the newly created process. */
	if_.R.rax = 0;	// child receives 0 for return of fork()
	do_iret (&if_);

error:
	/* fail to fork -> NOT push to child list of parent */
	sema_up(duplicate_done);	// waking up parent
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();
	// printf("pgcnt before load : %d\n", get_user_pages_cnt(PAL_USER));

	/* And then load the binary */
	lock_acquire(&filesys_lock);
	success = load (file_name, &_if);
	lock_release(&filesys_lock);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
		return -1;
	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}




/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct list *child_list = &thread_current()->child_list;

	if (child_tid > 0) {	// if valid tid,
		struct child *child = find_child(child_list, child_tid);
		if (child != NULL) {
			sema_down(&child->sema);	// waiting for child to be dead.

			int exit_code = child->exit_code;
			list_remove(&child->elem);
			free(child);
			return exit_code;
		}
	}
	return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	// process termination message
	printf ("%s: exit(%d)\n", curr->name, curr->exit_code);

	// parent and child
	old_level = intr_disable ();
	/* 부모에게 자식이(현재 프로세스가) 죽었음을 알게함 */
	/* sorry mama... */
	if(curr->sorry_mama != NULL){
		curr->sorry_mama->exit_code = curr->exit_code;
		sema_up(&curr->sorry_mama->sema);
	}

	/* 현재 프로세스의 child_list를 정리함 */
	/* 얌전히 있으면... 엄마가 금방 돌아올게...! 꼭..! */
	struct list *child_list = &curr->child_list;
	struct list_elem *e = list_head(child_list);

	while (!list_empty(child_list)) {
		struct list_elem *e = list_pop_front (child_list);
		struct child *child = list_entry(e, struct child, elem);
		if (child->sema.value == 0)		// child is still alive
			child->self_thread->sorry_mama = NULL;
		free(child);
	}
	intr_set_level (old_level);

	/* close all open files */
	/* exec() 시에는 fd_table이 유지되어야 하기 때문에,
		* process_cleanup() 밖에 위치시킴 */
	lock_acquire(&filesys_lock);
	for (char fd = 2; fd < FD_MAX; fd++) {
		file_close(curr->fd_table[fd]);
	}
	lock_release(&filesys_lock);

	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

	/* close executable file for this process */
	lock_acquire(&filesys_lock);
	file_close(curr->running_executable);
	curr->running_executable = NULL;
	lock_release(&filesys_lock);

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
	curr->rsp = NULL;
	curr->user_stack_bottom = NULL;
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;
	/* for parsing */
	char *ptr;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	// 널문자('\0') 끼워넣기 신공
	if((ptr = strchr((char *)file_name, ' '))){
		*ptr = '\0';
	}

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					// printf("phdr.p_type: %x\n", phdr.p_type);
					// printf("phdr.p_flags: %x\n", phdr.p_flags);
					// printf("phdr.p_offset: %x\n", phdr.p_offset);	// 찐 정보가 쓰여진 offset
					// printf("phdr.p_vaddr: %x\n", phdr.p_vaddr);
					// printf("phdr.p_paddr: %x\n", phdr.p_paddr);
					// printf("phdr.p_filesz: %x\n", phdr.p_filesz);
					// printf("phdr.p_memsz: %x\n", phdr.p_memsz);
					// printf("phdr.p_align: %x\n", phdr.p_align);
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					// printf("!@# file_page: %x\n", file_page);	// 세그먼트의 파일에서의 페이지 시작주소
					// printf("!@# mem_page: %x\n", mem_page);		// 가상메모리 안에서 세그먼트
					// printf("!@# page_offset: %x\n", page_offset);
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					}
					else {	// bss 영역은 파일에 정보가 저장될 필요가 없다(p_filesz==0).
							// 해당 영역 크기(p_memsz)만 알 수 있으면 된다.
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	if(ptr){
		*ptr = ' ';
	}
	parse_argument(file_name, if_);

	success = true;

	/* deny write on loaded excutable */
	file_deny_write(file);					// deny write on running executable of this process.
	t->running_executable = file;			// remember this file(excutable).
											// This file(excutable) will be closed in process_exit().

done:
	/* We arrive here whether the load is successful or not. */
	return success;
}



/*
	예시 : args-many   1 2 3 4 5 6 7
*/
void
parse_argument (void *f_name, struct intr_frame *if_) {
	uintptr_t rsp = if_->rsp;
	char *argv[LOADER_ARGS_LEN / 2 + 1];
	char *token, *save_ptr;
	int argc = 0;

	/* push token to user-stack and make argv */
	token = strtok_r ((char *)f_name, " ", &save_ptr);
	while (token != NULL) {
		rsp -= strlen(token) + 1;
		strlcpy(rsp, token, LOADER_ARGS_LEN+1);
		argv[argc++] = rsp;

		token = strtok_r (NULL, " ", &save_ptr);
	}

	/* word alignment */
	while ((rsp & 15) != 0) {
		rsp--;
		*(char *)rsp = 0;
	}
	
	argv[argc] = 0;		// null pointer sentinel

	/* rsp+8 16의 배수 align */
	if (argc % 2 == 0) {
		rsp -= 8;
		*(uintptr_t *)rsp = 0;
	}

	/* push argv to user-stack */
	int argv_size_b = (argc+1) * sizeof(char *);
	rsp -= argv_size_b;
	memcpy(rsp, argv, argv_size_b);

	/* false return address */
	rsp -= 8;
	*(uintptr_t *)rsp = 0;
	
	if_->rsp = rsp;
	if_->R.rdi = argc;
	if_->R.rsi = rsp+8;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	struct lazy_args *la = aux;

	struct file *file = thread_current()->running_executable;
	off_t ofs = la->ofs;
	size_t page_read_bytes = la->page_read_bytes;
	size_t page_zero_bytes = la->page_zero_bytes;

	file_seek(file, ofs);
	// read page_read_bytes
	if (file_read (file, page->va, page_read_bytes) != (int) page_read_bytes)
		return false;
	// set page_zero_bytes
	memset (page->va + page_read_bytes, 0, page_zero_bytes);

	free(la);	// FREE!:lazy_args
	page->uninit.aux = NULL;

	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */

		// MALLOC!:lazy_args
		struct lazy_args *lazy_args = malloc(sizeof(struct lazy_args));
		if (lazy_args == NULL)
			return false;
		lazy_args->argc = 4;
		lazy_args->ofs = ofs;
		lazy_args->page_read_bytes = page_read_bytes;
		lazy_args->page_zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, lazy_args))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately. */
	/* TODO: You should mark the page is stack. */

	if (!vm_alloc_page(VM_ANON | VM_STACK, stack_bottom, true))
		return false;

	/* TODO: If success, set the rsp accordingly. */
	if_->rsp = USER_STACK;

	return true;
}
#endif /* VM */
