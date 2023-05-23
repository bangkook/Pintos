#include "userprog/syscall.h"
#include <stdio.h>
#include <console.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"

typedef int pid_t;

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
sys_wait(pid_t pid){
  return process_wait(pid);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf("syscall : %d\n",*(uint32_t *)(f->esp));
  //hex_dump(f->esp, f->esp, 100, 1);
  // TODO : check if f-> is bad pointer

  int sys_code = *(int *)f->esp;

  switch (*(uint32_t *)(f->esp))
  {
  case SYS_HALT:
    /* code */
    break;
  
  case SYS_EXIT:
  {
    int status = *((uint32_t *)f->esp + 1);
    sys_exit(status);
    break;
  }
  case SYS_EXEC:
    break;

  case SYS_WAIT:
  {
    int pid = *((int*)f->esp + 1);
    f->eax = sys_wait(pid);
    break;
  }

  case SYS_CREATE:
    break;

  case SYS_REMOVE:
    break;

  case SYS_OPEN:
    break;

  case SYS_FILESIZE:
    break;

  case SYS_READ:
    break;

  case SYS_WRITE:
  {
    int fd = *((int*)f->esp + 1);
    void* buffer = (void*)(*((int*)f->esp + 2));
    unsigned size = *((unsigned*)f->esp + 3);

    f->eax = write(fd, buffer, size);

    break;
  }
  case SYS_SEEK:
    break;

  case SYS_TELL:
    break;

  case SYS_CLOSE:
    break;
    
  default:
    break;
  }

  //thread_exit ();
}
