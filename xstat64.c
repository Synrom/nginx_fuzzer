#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>

int main(){
	printf("r %d\n",O_RDONLY);
	printf("w %d\n",O_WRONLY);
	printf("rw %d\n",O_RDWR);
	printf("a %d\n",O_APPEND);
	printf("async %d\n",O_ASYNC);
	printf("cloexec %d\n",O_CLOEXEC);
	printf("creat %d\n",O_CREAT);
	printf("directory %d\n",O_DIRECTORY);
	printf("excl %d\n",O_EXCL);
	printf("noctty %d\n",O_NOCTTY);
	printf("nofollow %d\n",O_NOFOLLOW);
	printf("trunc %d\n",O_TRUNC);
//	printf("ttyinit %d\n",O_TTY_INIT);
//	printf("largefile %d\n",O_LARGEFILE);
	printf("sizeof(size_t) = %d\n",sizeof(size_t));
	return 0;
}
	
