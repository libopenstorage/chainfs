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
	}

	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t tid;
	char *mode;
	int c;

	if (argc != 2) {
		fprintf(stderr, "Usage %s chainfs-mode\n", argv[0]);
		return -1;
	}

	mode = (char *)argv[1];

	if (!strcmp(mode, "chainfs")) {
		pthread_create(&tid, NULL, launch, mode);

		sleep(2);

		fprintf(stderr, "Creating layers...\n");

		create_layer("layer1", NULL);
		create_layer("layer2", "layer1");

		fprintf(stderr, "Creating layers...\n");

		create_layer("layer1", NULL);
		create_layer("layer2", "layer1");
	} else if (!strcmp(mode, "dummyfs")) {
		pthread_create(&tid, NULL, launch, mode);
	} else {
		fprintf(stderr, "Unknown chainfs mode %s\n", mode);
		return -1;
	}

	fprintf(stderr, "Ready... Press 'q' to exit.\n");

	do {
		c = getchar();
	} while (c != 'q');

	stop_chainfs();

	return 0;
}
