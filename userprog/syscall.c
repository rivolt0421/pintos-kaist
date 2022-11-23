#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "threads/synch.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	syscall_handler_func *handler;

	handler = syscall_handlers[f->R.rax];
	if (handler) {
		handler(f);		// handle system call.
	}
	else {
		intr_dump_frame (f);
		PANIC ("Unexpected system call");
	}
		
}

/* This assertion should be used when
   the argument sent by user is POINTER TYPE */
void assert_valid_address(void * uaddr) {
	/* invalid if uaddr is null or kernel virtual address */
	if (!uaddr || is_kernel_vaddr(uaddr)) {
		thread_current()->exit_code = -1;
		thread_exit();
	}

	/* just check if uaddr is actually mapped to some physical address */
	if (!pml4_get_page(thread_current()->pml4, uaddr)) {
		thread_current()->exit_code = -1;
		thread_exit();
	}
}

/*
 * void
 * halt (void)
 */
void halt_syscall_handler (struct intr_frame *f) {
	power_off();
} 

/*
 * void
 * exit (int status)
 */
void exit_syscall_handler (struct intr_frame *f) {
	thread_current()->exit_code = f->R.rdi;
	thread_exit();
} 

void fork_syscall_handler (struct intr_frame *f) {

} 

void exec_syscall_handler (struct intr_frame *f) {

} 

void wait_syscall_handler (struct intr_frame *f) {

} 

void create_syscall_handler (struct intr_frame *f) {

} 

void remove_syscall_handler (struct intr_frame *f) {

} 

/*
 * int 
 * open (const char *file)
 */
void open_syscall_handler (struct intr_frame *f) {
	assert_valid_address(f->R.rdi);

	char *file_name = f->R.rdi;
	uintptr_t *fd_table = thread_current()->fd_table;
	uintptr_t *file_opened;

	/* check file_name and fd_count */
	if (!file_name || thread_current()->fd_count >= 16) {
		f->R.rax = -1;
		return;
	}
	lock_acquire(&filesys_lock);
	file_opened = filesys_open(file_name);
	lock_release(&filesys_lock);

	/* check the file has been successfully opened */
	if (!file_opened) {
		f->R.rax = -1;
		return;
	}
	
	/* find empty entry */
	for (char idx = 2; idx < 16; idx++) {
		if (!fd_table[idx]) {	// 2번부터 빈 공간 선형 탐색
			fd_table[idx] = file_opened;
			f->R.rax = idx;		// 유저에게 fd를 넘겨주는 순간
			return;
		}
	}

	/* should not be reached */
	f->R.rax = -1;
} 

/* 
 * int
 * filesize (int fd)
 */
void filesize_syscall_handler (struct intr_frame *f) {
	int fd = f->R.rdi;
	intptr_t *fd_table = thread_current()->fd_table;

	/* Cannot find file mapped by fd */
	if (fd < 2 || fd > 15 || fd_table[fd] == NULL) {
		f->R.rax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	int32_t f_len = file_length(fd_table[fd]);
	lock_release(&filesys_lock);

	f->R.rax = f_len;
} 

void read_syscall_handler (struct intr_frame *f) {

} 

void write_syscall_handler (struct intr_frame *f) {
	int fd = f->R.rdi;
	const void *buffer = f->R.rsi;
	unsigned size = f->R.rdx;

	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
	}

} 

void seek_syscall_handler (struct intr_frame *f) {

} 

void tell_syscall_handler (struct intr_frame *f) {

} 

/* 
 * void
 * close (int fd)
 */
void close_syscall_handler (struct intr_frame *f) {
	int fd = f->R.rdi;
	uintptr_t *fd_table = thread_current()->fd_table;

	/* fd validity check */
	if (fd < 2 || fd > 15) {
		f->R.rax = -1;
		return;
	}

	fd_table[fd] = NULL;
} 

void mmap_syscall_handler (struct intr_frame *f) {

}  

void munmap_syscall_handler (struct intr_frame *f) {

}  

void chdir_syscall_handler (struct intr_frame *f) {

}  

void mkdir_syscall_handler (struct intr_frame *f) {

}  

void readdir_syscall_handler (struct intr_frame *f) {

}  

void isdir_syscall_handler (struct intr_frame *f) {

}  

void inumber_syscall_handler (struct intr_frame *f) {

}  

void symlink_syscall_handler (struct intr_frame *f) {

}  

void dup2_syscall_handler (struct intr_frame *f) {

}  

void mount_syscall_handler (struct intr_frame *f) {

}  

void umount_syscall_handler (struct intr_frame *f) {

} 

