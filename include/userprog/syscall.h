#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct intr_frame;

/* Lock used by allocate_tid(). */
struct lock filesys_lock;

void syscall_init (void);

void halt_syscall_handler (struct intr_frame *);
void exit_syscall_handler (struct intr_frame *);
void fork_syscall_handler (struct intr_frame *);
void exec_syscall_handler (struct intr_frame *);
void wait_syscall_handler (struct intr_frame *);
void create_syscall_handler (struct intr_frame *);
void remove_syscall_handler (struct intr_frame *);
void open_syscall_handler (struct intr_frame *);
void filesize_syscall_handler (struct intr_frame *);
void read_syscall_handler (struct intr_frame *);
void write_syscall_handler (struct intr_frame *);
void seek_syscall_handler (struct intr_frame *);
void tell_syscall_handler (struct intr_frame *);
void close_syscall_handler (struct intr_frame *);

void mmap_syscall_handler (struct intr_frame *); 
void munmap_syscall_handler (struct intr_frame *); 

void chdir_syscall_handler (struct intr_frame *); 
void mkdir_syscall_handler (struct intr_frame *); 
void readdir_syscall_handler (struct intr_frame *); 
void isdir_syscall_handler (struct intr_frame *); 
void inumber_syscall_handler (struct intr_frame *); 
void symlink_syscall_handler (struct intr_frame *); 

void dup2_syscall_handler (struct intr_frame *); 
void mount_syscall_handler (struct intr_frame *); 
void umount_syscall_handler (struct intr_frame *);

#define SYSCALL_CNT 23
typedef void syscall_handler_func (struct intr_frame *);
static syscall_handler_func *syscall_handlers[SYSCALL_CNT] = {
	halt_syscall_handler,
	exit_syscall_handler,
	fork_syscall_handler,
	exec_syscall_handler,
    wait_syscall_handler,
    create_syscall_handler,
    remove_syscall_handler,
    open_syscall_handler,
    filesize_syscall_handler,
    read_syscall_handler,
    write_syscall_handler,
    seek_syscall_handler,
    tell_syscall_handler,
    close_syscall_handler,
    
	mmap_syscall_handler,
    munmap_syscall_handler,
    
	chdir_syscall_handler,
    mkdir_syscall_handler,
    readdir_syscall_handler,
    isdir_syscall_handler,
    inumber_syscall_handler,
    symlink_syscall_handler,
    
	dup2_syscall_handler,
    mount_syscall_handler,
    umount_syscall_handler
};

#endif /* userprog/syscall.h */
