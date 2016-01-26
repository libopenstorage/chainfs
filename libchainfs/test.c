#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include "chainfs.h"

void *launch(void *arg)
{
	char *mode = (char *)arg;

	if (!strcmp(mode, "chainfs")) {
		start_chainfs(mode_chainfs, "/var/lib/openstorage/chainfs");
	} else if (!strcmp(mode, "dummyfs")) {
		start_chainfs(mode_dummyfs, "/var/lib/openstorage/chainfs");
	} else {
		fprintf(stderr, "Unknown chainfs mode %s\n", mode);
	}

	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t tid;
	int c;

	if (argc != 2) {
		fprintf(stderr, "Usage %s chainfs-mode\n", argv[0]);
		return -1;
	}

	pthread_create(&tid, NULL, launch, argv[1]);

	sleep(2);

	fprintf(stderr, "Creating layers...\n");

	create_layer("layer1", NULL);
	create_layer("layer2", "layer1");

	fprintf(stderr, "Ready... Press 'q' to exit.\n");
	do {
		c = getchar();
	} while (c != 'q');

	return 0;
}
