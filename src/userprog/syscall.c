#include "userprog/syscall.h"
#include <stdio.h>
#include <console.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "threads/vaddr.h"

typedef int pid_t;
static struct lock files_sync_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int
write(int fd, const void* buffer, unsigned size) {
  //printf("%d\n", fd);
  if(fd == 1) {
    putbuf(buffer, size);
    //printf("size: %d\n", size);
    return size;
  }
  return -1;
}

static void
sys_exit(int status) {
  //thread_current()->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

static int
sys_exec(const char *cmd){

  struct thread *cur = thread_current ();

  if (!cmd )
    return -1;
  
  if (!is_user_vaddr (cmd)) 
    return -1;
  
  if( pagedir_get_page (cur->pagedir, cmd) == NULL)
    return -1;

  lock_acquire(&files_sync_lock);
	pid_t child_tid = process_execute(cmd);
  lock_release(&files_sync_lock);
	return child_tid;

}

static int
sys_wait(pid_t pid){
  return process_wait(pid);
}

static void validate_pointer(const void* vaddr) {
  if(!is_user_vaddr(vaddr))
    sys_exit(-1);
}
static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  for(int i = 0; i < 4; i++) {
    validate_pointer(f->esp + i);
  }

  int sys_code = *(int *)f->esp;

  switch (sys_code)
  {
  case SYS_HALT:
    /* code */
    break;
  
  case SYS_EXIT:
  {
    validate_pointer(f->esp + 4);
    int status = *((uint32_t *)f->esp + 1);
    sys_exit(status);
    break;
  }
  case SYS_EXEC:
    break;

  case SYS_WAIT:
  {
    validate_pointer(f->esp + 4);
    int pid = *((int*)f->esp + 1);
    f->eax = sys_wait(pid);
    break;
  }

  case SYS_CREATE:
    validate_pointer(f->esp + 4);
    validate_pointer(f->esp + 8);
    break;

  case SYS_REMOVE:
    validate_pointer(f->esp + 4);
    break;

  case SYS_OPEN:
    validate_pointer(f->esp + 4);
    break;

  case SYS_FILESIZE:
    validate_pointer(f->esp + 4);
    break;

  case SYS_READ:
    validate_pointer(f->esp + 4);
    break;

  case SYS_WRITE:
  {
    validate_pointer(f->esp + 12);

    int fd = *((int*)f->esp + 1);
    void* buffer = (void*)(*((int*)f->esp + 2));
    unsigned size = *((unsigned*)f->esp + 3);

    f->eax = write(fd, buffer, size);

    break;
  }
  case SYS_SEEK:
   validate_pointer(f->esp + 4);
    break;

  case SYS_TELL:
   validate_pointer(f->esp + 4);
    break;

  case SYS_CLOSE:
    validate_pointer(f->esp + 4);
    break;
    
  default:
    break;
  }

  //thread_exit ();
}
