#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);
bool install_page(void *, void *, bool);
bool setup_stack(struct intr_frame *if_);
bool lazy_load_segment(struct page *page, void *aux);

struct child
{
    struct thread *self_thread;
    tid_t tid;
    int exit_code;
    struct list_elem elem;
    struct semaphore sema;
};

#endif /* userprog/process.h */
