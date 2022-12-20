#include "userprog/syscall.h"
#include "userprog/process.h"
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
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "vm/vm.h"

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
	thread_current()->rsp = f->rsp;

	handler = syscall_handlers[f->R.rax];
	if (handler) {
		handler(f);		// handle system call.
	}
	else {
		intr_dump_frame (f);
		PANIC ("Unexpected system call");
	}

	thread_current()->rsp = NULL;
}

/* This assertion should be used when
   the argument sent by user is POINTER TYPE */
void assert_valid_address(void * uaddr, bool try_to_write) {
	/* invalid if uaddr is null or kernel virtual address */
	if (!uaddr || is_kernel_vaddr(uaddr)) {
		goto terminate;
	}

	/* check if user can expect data at the address,
	 * and check writable for read() system call. (we have to write in user buffer to handle read() system call) */
	struct page *page = spt_find_page(&thread_current()->spt, uaddr);

	// TODO : 버퍼의 끝 지점도 page 존재하는지 확인해야 할듯.
	if (page == NULL) {
		/* check if stack growth case */
		// later
		// 스택 영역은 위에서부터 채워짐을 상기해보자.

		goto terminate;
	}
	
	if (try_to_write && page->writable == 0)
		goto terminate;

	return;	// success.

terminate:
	thread_current()->exit_code = -1;
	thread_exit();
}

struct child *find_child (struct list *child_list, int tid) {
	struct list_elem *e = list_head(child_list);

	while ((e = list_next(e)) != list_end(child_list)) {
		struct child *child = list_entry(e, struct child, elem);
		if (tid == child->tid) {
			return child;
		}
	}

	return NULL;
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

/*
 * pid_t
 * fork (const char *thread_name)
 */
void fork_syscall_handler (struct intr_frame *f) {
	struct thread *curr = thread_current();
	struct list *child_list = &curr->child_list;
	int tid = process_fork(f->R.rdi, f);

	if (tid > 0) {	// if valid tid,
		struct child *child = find_child(child_list, tid);
		if (child != NULL) {
			f->R.rax = tid;
			return;
		}
	}

	/* including thread_create() fail, do_fork() fail */
	f->R.rax = TID_ERROR;
} 

/*
 * int 
 * exec (const char *file)
 */
void exec_syscall_handler (struct intr_frame *f) {
	assert_valid_address(f->R.rdi, false);

	char *arg, *arg_copy;
	arg = f->R.rdi;

	/* Make a copy of argument */
	arg_copy = palloc_get_page (0);
	if (arg_copy != NULL) {
		strlcpy(arg_copy, arg, PGSIZE);

		/* Never return if succeed */
		int result = process_exec(arg_copy);
	}
	/* Reaches here when failure. */
	thread_current()->exit_code = -1;
	thread_exit();
} 

/*
 * int 
 * wait (pid_t pid)
 */
void wait_syscall_handler (struct intr_frame *f) {
	int tid = f->R.rdi;

	f->R.rax = process_wait(tid);
} 

/*
 * bool
 * create (const char *file, unsigned initial_size)
 */
void create_syscall_handler (struct intr_frame *f) {
	assert_valid_address(f->R.rdi, false);

	char *name = f->R.rdi;
	unsigned initial_size = f->R.rsi;
	lock_acquire(&filesys_lock);
	bool success = filesys_create(name, initial_size, 0);
	lock_release(&filesys_lock);

	f->R.rax = success;
}

/*
 * bool
 * remove (const char *file)
 */
void remove_syscall_handler (struct intr_frame *f) {
	assert_valid_address(f->R.rdi, false);
	
	char *name = f->R.rdi;
	/* cannot remove root directory */
	if (strcmp(name, "/") == 0) {
		f->R.rax = false;
		return;		
	}
	
	lock_acquire(&filesys_lock);
	bool success = filesys_remove(name);
	lock_release(&filesys_lock);

	f->R.rax = success;
} 

/*
 * int
 * open (const char *file)
 */
void open_syscall_handler (struct intr_frame *f) {
	assert_valid_address(f->R.rdi, false);

	char *file_name = f->R.rdi;
	uintptr_t *fd_table = thread_current()->fd_table;
	uintptr_t file_opened;

	/* check file_name and fd_count */
	if (!file_name || *file_name == '\0' || thread_current()->fd_count >= FD_MAX) {
		f->R.rax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	if (strcmp(file_name, "/") == 0)	// for opening root directory
		file_opened = dir_open_root();
	else
		file_opened = filesys_open(file_name);
	lock_release(&filesys_lock);

	/* check the file has been successfully opened */
	if (!file_opened) {
		f->R.rax = -1;
		return;
	}
	
	/* find empty entry */
	for (char idx = 2; idx < FD_MAX; idx++) {
		if (!fd_table[idx]) {	// 2번부터 빈 공간 선형 탐색
			fd_table[idx] = file_opened;
			f->R.rax = idx;		// 유저에게 fd를 넘겨주는 순간
			thread_current()->fd_count += 1;
			return;
		}
	}

	/* should not be reached */
	NOT_REACHED();
}

/* 
 * int
 * filesize (int fd)
 */
void filesize_syscall_handler (struct intr_frame *f) {
	int fd = f->R.rdi;
	intptr_t *fd_table = thread_current()->fd_table;

	/* fd validity check */
	if (fd < 2 || fd >= FD_MAX || fd_table[fd] == NULL) {
		f->R.rax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	int32_t f_len = file_length(fd_table[fd]);
	lock_release(&filesys_lock);

	f->R.rax = f_len;
} 

/* 
 * int
 * read (int fd, void *buffer, unsigned size)
 */
void read_syscall_handler (struct intr_frame *f) {
	assert_valid_address(f->R.rsi, true);

	int fd = f->R.rdi;
	char *buffer = f->R.rsi;
	unsigned size = f->R.rdx;
	intptr_t *fd_table = thread_current()->fd_table;
	int32_t read_bytes = 0;
	int i = 0;

	if (fd == STDIN_FILENO) {
		while(size-- > 0) {
			buffer[i++] = (char) input_getc();
			read_bytes++;
		}
	}
	else {
		/* fd validity check */
		if (fd < 2 || fd >= FD_MAX || fd_table[fd] == NULL) {
			f->R.rax = -1;
			return;
		}
		lock_acquire(&filesys_lock);
		read_bytes = file_read(fd_table[fd], buffer, size);
		lock_release(&filesys_lock);
	}
	f->R.rax = read_bytes;
} 

/* 
 * int
 * write (int fd, const void *buffer, unsigned size)
 */
void write_syscall_handler (struct intr_frame *f) {
	assert_valid_address(f->R.rsi, false);

	int fd = f->R.rdi;
	const void *buffer = f->R.rsi;
	unsigned size = f->R.rdx;
	intptr_t *fd_table = thread_current()->fd_table;
	int32_t written_bytes = 0;

	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		written_bytes = size;
	}
	else {
		/* fd validity check */
		if (fd < 2 || fd >= FD_MAX || fd_table[fd] == NULL) {
			f->R.rax = -1;
			return;
		}
		/* cannot write to directory */
		uintptr_t file_or_dir = fd_table[fd];
		if (inode_get_type(*(uintptr_t *)file_or_dir) == 1) {
			f->R.rax = -1;
			return;			
		}

		lock_acquire(&filesys_lock);
		written_bytes = file_write(fd_table[fd], buffer, size);
		lock_release(&filesys_lock);
	}
	f->R.rax = written_bytes;
} 

/* 
 * void
 * seek (int fd, unsigned position)
 */
void seek_syscall_handler (struct intr_frame *f) {
	int fd = f->R.rdi;
	uintptr_t *fd_table = thread_current()->fd_table;
	unsigned new_pos = f->R.rsi;

	/* fd validity check */
	if (fd < 2 || fd >= FD_MAX || fd_table[fd] == NULL)
		
	/* new position validity check */
	if (new_pos < 0)
		return;
	
	lock_acquire(&filesys_lock);
	file_seek(fd_table[fd], new_pos);
	lock_release(&filesys_lock);
}

/* 
 * unsigned
 * tell (int fd)
 */
void tell_syscall_handler (struct intr_frame *f) {
	int fd = f->R.rdi;
	uintptr_t *fd_table = thread_current()->fd_table;
	unsigned position = 0;

	/* fd validity check */
	if (fd < 2 || fd >= FD_MAX || fd_table[fd] == NULL) {
		f->R.rax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	position = file_tell(fd_table[fd]);
	lock_release(&filesys_lock);

	f->R.rax = position;
} 

/* 
 * void
 * close (int fd)
 */
void close_syscall_handler (struct intr_frame *f) {
	int fd = f->R.rdi;
	uintptr_t *fd_table = thread_current()->fd_table;

	/* fd validity check */
	if (fd < 2 || fd >= FD_MAX || fd_table[fd] == NULL)
		return;	// silently fail...

	lock_acquire(&filesys_lock);
	// //
	// printf ("Printing file to the console...\n");
	// char *buffer;
	// buffer = palloc_get_page (PAL_ASSERT);
	// file_seek(fd_table[fd], 0);
	// for (;;) {
	// 	off_t pos = file_tell (fd_table[fd]);
	// 	off_t n = file_read (fd_table[fd], buffer, PGSIZE);
	// 	if (n == 0)
	// 		break;

	// 	hex_dump (pos, buffer, n, true); 
	// }
	// palloc_free_page (buffer);
	// //
	uintptr_t file_or_dir = fd_table[fd];
	if (inode_get_type(*(uintptr_t *)file_or_dir) == 0)
		file_close(fd_table[fd]);
	else if (inode_get_type(*(uintptr_t *)file_or_dir) == 1)
		dir_close(fd_table[fd]);
	else 
		PANIC("todo : close symbolic link");
	lock_release(&filesys_lock);

	fd_table[fd] = NULL;
	ASSERT(thread_current()->fd_count > 2);
	thread_current()->fd_count -= 1;
} 

/* 
 * int
 * dup2 (int oldfd, int newfd)
 */
void dup2_syscall_handler (struct intr_frame *f) {

}  

/* 
 * void *
 * mmap (void *addr, size_t length, int writable, int fd, off_t offset)
 * 
 * Maps `length` bytes the file open as `fd` starting from `offset` byte
 * into the process's virtual address space at `addr`.
 */
void mmap_syscall_handler (struct intr_frame *f) {

	void *addr 		= f->R.rdi;
	size_t length 	= f->R.rsi;
	int writable	= f->R.rdx;
	int fd 			= f->R.r10;
	off_t offset 	= f->R.r8;

	uintptr_t *fd_table = thread_current()->fd_table;

	lock_acquire(&filesys_lock);

// @ if addr is 0, it must fail, because some Pintos code assumes virtual page 0 is not mapped.
// @ It must fail if addr is not page-aligned.
	if (addr == 0 || is_kernel_vaddr(addr) || pg_ofs(addr) != 0)
		goto fail;

// @ the file descriptors representing console input and output are not mappable.
	if (fd < 2 || fd >= FD_MAX || fd_table[fd] == NULL)
		goto fail;
	
// @ Your mmap should also fail when length is zero.
// @ A call to mmap may fail if the file opened as fd has a length of zero bytes.
	size_t file_size = file_length (fd_table[fd]);
	if (length <= 0 || file_size <= 0)
		goto fail;

	if (pg_ofs(offset) != 0 || file_size <= offset)
		goto fail;

// In Linux, if addr is NULL, the kernel finds an appropriate address at which to create the mapping.
// For simplicity, you can just attempt to mmap at the given addr.

// @ if the range of pages mapped overlaps any existing set of mapped pages,
//   including the stack or pages mapped at executable load time.
// @ also should not overlap kernel space.
	void *each_page = addr;
	void *boundary = addr + length;
	struct page *page = NULL;

	if (is_kernel_vaddr(boundary - 1))
		goto fail;

	while (each_page < boundary) {
		page = spt_find_page(&thread_current()->spt, each_page);
		if (page != NULL)	// page should not exist.
			break;

		each_page += PGSIZE;
	}
	if (page != NULL)
		goto fail;

/* here we can say that user argumnets are valid. */
	f->R.rax = do_mmap(addr, length, writable, fd_table[fd], offset);
	lock_release(&filesys_lock);

	return;
	
fail:
	lock_release(&filesys_lock);
	f->R.rax = NULL;
	return;
}  

/* 
 * void
 * munmap (void *addr)
 */
void munmap_syscall_handler (struct intr_frame *f) {
	void *addr = f->R.rdi;
	struct list *sp_list = &thread_current()->spt.sp_list;
	struct page *first_page = spt_find_page(&thread_current()->spt, addr);

	/* addr validity check */
	if (first_page == NULL) {
		printf("bad addr for munmap()");
		return;	// silently fail...
	}

	enum vm_type type = VM_TYPE(first_page->operations->type);
	void *root_addr = NULL;
	if (type == VM_FILE)
		root_addr = first_page->file.root_addr;
	else if (type == VM_UNINIT) {
		struct lazy_args *la = first_page->uninit.aux;
		root_addr = la->root_addr;
	}

	if (root_addr == NULL || root_addr != addr) {
		printf("bad addr for munmap()");
		return;	// silently fail...
	}
	/* end of addr validity check */

	do_munmap(addr);

}  

/* 
 * bool
 * chdir (const char *dir)
 */
void chdir_syscall_handler (struct intr_frame *f) {
	assert_valid_address(f->R.rdi, false);

	const char *dir_name = f->R.rdi;
	bool success = false;

	lock_acquire(&filesys_lock);
	uintptr_t dir = NULL;
	if (strcmp(dir_name, "/") == 0)	// for opening root directory
		dir = dir_open_root();
	else
		dir = filesys_open(dir_name);
		
	if (dir != NULL) {
		dir_close(thread_current()->cwd);
		thread_current()->cwd = dir;
		success = true;
	}
	lock_release(&filesys_lock);

	f->R.rax = success;
}  

/* 
 * bool
 * mkdir (const char *dir)
 */
void mkdir_syscall_handler (struct intr_frame *f) {
	assert_valid_address(f->R.rdi, false);

	lock_acquire(&filesys_lock);

	char *dir_name = f->R.rdi;
	bool success = filesys_create(dir_name, 16 * 20, 1);	// sizeof (struct dir_entry) == 20

	lock_release(&filesys_lock);

	f->R.rax = success;
}  

/* 
 * bool
 * readdir (int fd, char name[READDIR_MAX_LEN + 1])
 */
void readdir_syscall_handler (struct intr_frame *f) {
	assert_valid_address(f->R.rsi, false);

	int fd = f->R.rdi;
	char *name = f->R.rsi;
	intptr_t *fd_table = thread_current()->fd_table;

	/* fd validity check */
	if (fd < 2 || fd >= FD_MAX || fd_table[fd] == NULL) {
		f->R.rax = -1;
		return;
	}
	/* file should represents directory */
	uintptr_t dir = fd_table[fd];
	if (inode_get_type(*(uintptr_t *)dir) != 1) {
		f->R.rax = -1;
		return;
	}

	f->R.rax = dir_readdir(dir, name);
}

/* 
 * bool
 * isdir (int fd)
 */
void isdir_syscall_handler (struct intr_frame *f) {
	int fd = f->R.rdi;
	intptr_t *fd_table = thread_current()->fd_table;

	/* fd validity check */
	if (fd < 2 || fd >= FD_MAX || fd_table[fd] == NULL) {
		f->R.rax = -1;
		return;
	}
	
	uintptr_t file_or_dir = fd_table[fd];
	f->R.rax = inode_get_type(*(uintptr_t *)file_or_dir) == 1;
}  

/* 
 * int
 * inumber (int fd)
 */
void inumber_syscall_handler (struct intr_frame *f) {
	int fd = f->R.rdi;
	intptr_t *fd_table = thread_current()->fd_table;

	/* fd validity check */
	if (fd < 2 || fd >= FD_MAX || fd_table[fd] == NULL) {
		f->R.rax = -1;
		return;
	}

	uintptr_t file_or_dir = fd_table[fd];
	f->R.rax = inode_get_inumber(*(uintptr_t *)file_or_dir);
}  

/* 
 * int
 * symlink (const char* target, const char* linkpath)
 */
void symlink_syscall_handler (struct intr_frame *f) {

}  

/* 
 * int
 * mount (const char *path, int chan_no, int dev_no)
 */
void mount_syscall_handler (struct intr_frame *f) {

}  

/* 
 * int
 * umount (const char *path)
 */
void umount_syscall_handler (struct intr_frame *f) {

} 

