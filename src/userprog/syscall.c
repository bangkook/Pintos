#include "userprog/syscall.h"
#include <stdio.h>
#include <console.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"

typedef int pid_t;
static struct lock files_sync_lock;

static void syscall_handler (struct intr_frame *);

struct open_file
{
    struct list_elem file_elem;
    struct file *file_ptr;
    int fd;
};

void
syscall_init (void) 
{
  lock_init(&files_sync_lock);

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void validate_pointer(const void* vaddr) {
  if(!is_user_vaddr(vaddr)|| vaddr == NULL || vaddr < (void *) 0x08048000)
    sys_exit(-1);
}

void validate_buffer (void *buffer, unsigned size)
{
  unsigned i;
  char *ptr  = (char * )buffer;
  for (i = 0; i < size; i++)
    {
      validate_pointer((const void *) ptr);
      ptr++;
    }
}

static void
halt() {
  shutdown_power_off();
}

bool
sys_create (const char *file_name, unsigned size)
{
  bool status;
  // if(file_name==NULL){
  //   sys_exit(-1);
  // }
  lock_acquire (&files_sync_lock);
  status = filesys_create(file_name, size);  
  lock_release (&files_sync_lock);
  return status;
}

bool
sys_remove(const char *file_name){
  bool status;
  // if(file_name==NULL){
  //   sys_exit(-1);
  // }
  lock_acquire (&files_sync_lock);
  status = filesys_remove(file_name);  
  lock_release (&files_sync_lock);
  return status;
}


static int
sys_write(int fd, const void* buffer, unsigned size) {
  lock_acquire(&files_sync_lock);
  // if(size == 0 || buffer == NULL){
  //   lock_release(&files_sync_lock);
  //   return 0;
  // }
  
  // // Validate buffer  
  // for (unsigned i = 0; i < size; i++) {
  //   if (((char*)buffer)[i] == '\0') {
  //       lock_release(&files_sync_lock);
  //       return -1;  // Invalid buffer                 
  //   }
  // }

  //printf("%d\n", fd);
  if(fd == 1) { // writes to the console
    putbuf(buffer, size);
    lock_release(&files_sync_lock);
    //printf("size: %d\n", size);
    return size;
  }
  else if(fd == 0 || list_empty(&thread_current()->file_descriptors)){
    lock_release(&files_sync_lock);
    //printf("size: %d\n", size);
    return 0;
  }

  // struct list_elem *tmp = list_begin(&thread_current()->file_descriptors);
  // while(tmp != list_end(&thread_current()->file_descriptors)){
  struct list_elem *temp;
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next){
    struct open_file *t = list_entry(temp, struct open_file, file_elem);
      if (t->fd == fd)
      {
        int bytes_written = (int) file_write(t->file_ptr, buffer, size);
        lock_release(&files_sync_lock);
        return bytes_written;
      }
    // tmp = list_next(tmp);
  }

  lock_release(&files_sync_lock);
  if (size == 0) return 0;
  else return -1;
}

static int sys_read (int fd, void *buffer, unsigned size)
{

  // validate_buffer(buffer,size);
  // if(buffer == NULL){
  //   sys_exit(-1);
  // }
  // void * phys_page_ptr = (void *) pagedir_get_page(thread_current()->pagedir, (const void*)buffer);
  // if( phys_page_ptr == NULL)
  //   sys_exit(-1);

  lock_acquire(&files_sync_lock);
  if(size == 0){
    lock_release(&files_sync_lock);
    return 0;//0
  }

  if (fd == 0)
  {
    lock_release(&files_sync_lock);
    return (int) input_getc();
  }

  if (fd == 1 || list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&files_sync_lock);
    return 0;//-1
  }

    struct list_elem *e;
  struct open_file *t = NULL;
  for (e = list_begin(&thread_current()->file_descriptors);
       e != list_end(&thread_current()->file_descriptors);
       e = list_next(e)) {
    struct open_file *f = list_entry(e, struct open_file, file_elem);
    if (f->fd == fd) {
      t = f;
      break;
    }
  }

  if (t == NULL) {
    lock_release(&files_sync_lock);
    return -1;
  }

  int bytes = file_read(t->file_ptr, buffer, size);
  lock_release(&files_sync_lock);
  return bytes;

}


static int sys_open (const char *file){
  lock_acquire(&files_sync_lock);
  // if(file == NULL){
  //   lock_release(&files_sync_lock);
  //   sys_exit(-1);
  // }
  struct file* myFile_ptr = filesys_open(file);
  if(myFile_ptr == NULL){
    lock_release(&files_sync_lock);
    return -1;
  }
  struct open_file* new_file = malloc(sizeof(struct open_file));
  new_file->file_ptr = myFile_ptr;
  int fd = thread_current()->fd_count;
  thread_current()->fd_count += 1;
  new_file->fd = fd;
  list_push_front(&thread_current ()->file_descriptors, &new_file->file_elem);
  lock_release(&files_sync_lock);
  return fd;
}

static void 
sys_close (int fd)
{
  
  lock_acquire(&files_sync_lock);

  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&files_sync_lock);
    return;
  }
  struct list_elem *tmp = list_begin(&thread_current()->file_descriptors);

  while(tmp != list_end(&thread_current()->file_descriptors)){
    struct open_file *t = list_entry(tmp, struct open_file, file_elem);
      if (t->fd == fd)
      {
        file_close(t->file_ptr);
        list_remove(&t->file_elem);
        lock_release(&files_sync_lock);
        return;
      }
    tmp = list_next(tmp);
  }
 
  lock_release(&files_sync_lock);

  return;
}

static int 
sys_filesize (int fd)
{
  lock_acquire(&files_sync_lock);

  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&files_sync_lock);
    return -1;
  }

  struct list_elem *temp;
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct open_file *t = list_entry (temp, struct open_file, file_elem);
      if (t->fd == fd)
      {
        int length =(int) file_length(t->file_ptr);
        lock_release(&files_sync_lock);
        return length;
      }
  }

  lock_release(&files_sync_lock);
  return -1;
}

static void
sys_exit(int status) {
  thread_current()->exit_status = status;

  //mariam edit it if you want
  struct list_elem *tmp = list_begin(&thread_current()->file_descriptors);
  lock_acquire(&files_sync_lock);
  while(tmp != list_end(&thread_current()->file_descriptors)){
    struct open_file *t = list_entry(tmp, struct open_file, file_elem);
        file_close(t->file_ptr);
        list_remove(&t->file_elem);
        
    tmp = list_next(tmp);
  }
  lock_release(&files_sync_lock);
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

static int
sys_exec(const char *cmd){
  struct thread *cur = thread_current ();
  
  void * phys_page_ptr = (void *) pagedir_get_page(thread_current()->pagedir, (const void*)cmd);
  if( phys_page_ptr == NULL)
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
    {
      halt();
      break;
    }
  
  case SYS_EXIT:
  {
    validate_pointer(f->esp + 4);
    int status = *((uint32_t *)f->esp + 1);
    sys_exit(status);
    break;
  }
  case SYS_EXEC:
  {
    validate_pointer(f->esp + 4);
    char* cmd = (char*)(*((int*)f->esp + 1));
    //printf("cmd: %s\n", cmd);
    f->eax = sys_exec (cmd);
    break;
  }

  case SYS_WAIT:
  {
    validate_pointer(f->esp + 4);
    int pid = *((int*)f->esp + 1);
    f->eax = sys_wait(pid);
    break;
  }

  case SYS_CREATE:
    {
    validate_pointer(f->esp + 4);
    validate_pointer(f->esp + 8);
    char* file=(char*)(*((int*)f->esp + 1));
    unsigned size = *((int*)f->esp + 2);
    if(file== NULL)sys_exit(-1);
    f->eax=sys_create(file,size);
    break;
  }

  case SYS_REMOVE:
    {
      validate_pointer(f->esp + 4);
      char* file=(char*)(*((int*)f->esp + 1));
      if(file== NULL)sys_exit(-1);
      f->eax=sys_remove(file);
      break;
    }

  case SYS_OPEN:{
    validate_pointer(f->esp + 4);
    char* file = (char*) (*((int*)f->esp + 1));
    if(file== NULL)sys_exit(-1);
    f->eax = sys_open(file);
    break;
  }
    

  case SYS_FILESIZE:
  {
    validate_pointer(f->esp + 4);
    int fd = *((int*)f->esp + 1);
    f->eax = sys_filesize(fd);
    break;
  }

  case SYS_READ:
    {
    validate_pointer(f->esp + 12);
    validate_pointer(f->esp + 8);
    validate_pointer(f->esp + 4);
    
    int fd = *((int*)f->esp + 1);
    void* buffer = (void*)(*((int*)f->esp + 2));

    unsigned size = *((unsigned*)f->esp + 3);
    validate_buffer(buffer,size);
    f->eax = sys_read(fd, buffer, size);

    break;
  }

  case SYS_WRITE:
  {
    validate_pointer(f->esp + 12);
    validate_pointer(f->esp + 8);
    validate_pointer(f->esp + 4);
    
    int fd = *((int*)f->esp + 1);
    void* buffer = (void*)(*((int*)f->esp + 2));

    unsigned size = *((unsigned*)f->esp + 3);
    validate_buffer(buffer,size);
    f->eax = sys_write(fd, buffer, size);

    break;
  }
  case SYS_SEEK:
   validate_pointer(f->esp + 4);
    break;

  case SYS_TELL:
   validate_pointer(f->esp + 4);
    break;

  case SYS_CLOSE:
   {
    validate_pointer(f->esp + 4);
    sys_close(*((int*)f->esp + 1));
    break;
    }
    
  default:
    sys_exit(-1);
    break;
  }

  //thread_exit ();
}
