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

void halt_syscall_handler (struct intr_frame *f) {
	power_off();
} 

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

void open_syscall_handler (struct intr_frame *f) {
	char *file_name = f->R.rdi;
	struct file *fdt = thread_current()->fdt;
	char idx;
	for (idx = 2; idx < 17; idx++) {
		if (!fdt[idx]) {								// found empty entry
			if (fdt[idx] = filesys_open(file_name)) {	// if success to open
				f->R.rax = idx;
				return;
			}
			else {										// if fail to open
				f->R.rax = -1;
				return;
			}
		}
	}
	/* File descriptor table is full. */
	f->R.rax = -1;
} 

void filesize_syscall_handler (struct intr_frame *f) {

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

void close_syscall_handler (struct intr_frame *f) {

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

