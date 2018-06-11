#define _GNU_SOURCE     /* Needed to get O_LARGEFILE definition */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define LOG_ERROR(msg)		\
	do {                    \
		perror(msg);        \
		exit(EXIT_FAILURE); \
	} while (0)

#define BUFSIZE 		(1000 * (sizeof(struct inotify_event) + NAME_MAX + 1))
#define BAD_HASH_FILE 	"/home/parallels/Documents/bad_hash.txt"
#define WATCH_PATH 		"/home/parallels/watch_files"

void print_hash(unsigned char* hash)
{
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        printf("%02x", hash[i]);
    }

    printf("\n");
}

unsigned char hextoint(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';

    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;

    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    LOG_ERROR("Hex transforming failed");
}

unsigned char* get_bad_hash()
{
    FILE* file = fopen(BAD_HASH_FILE, "r");
    if (!file) {
        LOG_ERROR("Open bad hash file failed");
    }

    unsigned char buffer[2 * MD5_DIGEST_LENGTH];
    fscanf(file, "%s", buffer);
    printf("buffer: %s", buffer);

    int i = 0;
    unsigned char* result = (unsigned char*)calloc(MD5_DIGEST_LENGTH, sizeof(unsigned char));
    for (i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        result[i] = (hextoint(buffer[2 * i]) << 4) + hextoint(buffer[2 * i + 1]);
    }

    fclose(file);
    return result;
}

unsigned char* calculate_file_md5(const char* filename)
{
    FILE* file = fopen(filename, "r+");
    if (!file) {
        printf("calculate_file_md5: %s can't be opened\n", filename);
        return NULL;
    }

    MD5_CTX context;
    unsigned char data[1024];
    MD5_Init(&context);

    int bytes = 0;
    while ((bytes = fread(data, 1, 1024, file)) != 0)
        MD5_Update(&context, data, bytes);

    unsigned char* result = (unsigned char*)calloc(MD5_DIGEST_LENGTH, sizeof(unsigned char));
    MD5_Final(result, &context);
    fclose(file);
    return result;
}

int cmp_hashes(unsigned char* lhs, unsigned char* rhs) 
{
    int i = 0;
    for (i = 0; i < MD5_DIGEST_LENGTH; ++i)
        if (lhs[i] != rhs[i])
            return 0;

    return 1;
}


/*
int check_file(const char* filename) 
{
    unsigned char* bad_hash = get_bad_hash();
    unsigned char* file_hash = calculate_file_md5(filename);
    if (!file_hash)
        return 1;

	int result = !cmp_hashes(file_hash, bad_hash);

    free(file_hash);
	free(bad_hash);
	return result;
}
*/

int check_file(const char* filename)
{
	unsigned char* file_hash = calculate_file_md5(filename);
	
	FILE* file = fopen(BAD_HASH_FILE, "r");
	if (!file) {
		LOG_ERROR("Open bad hash file failed");
	}

	unsigned char buffer[2 * MD5_DIGEST_LENGTH];
	unsigned char result[MD5_DIGEST_LENGTH];
	int i = 0;
	while (fscanf(file, "%s", buffer) > 0) {
		printf("buffer: %s\n", buffer);
		for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
			result[i] = (hextoint(buffer[2 * i]) << 4) + hextoint(buffer[2 * i + 1]);
		}

		if (cmp_hashes(file_hash, result)) {
			free(file_hash);
			fclose(file);
			return 0;
		}
		memset(result, 0, MD5_DIGEST_LENGTH);
		memset(buffer, 0, MD5_DIGEST_LENGTH);		
	}
	free(file_hash);
	return 1;
}


int check_event(struct inotify_event* event) 
{
    if (!(event->mask & (IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO)))
		return 1;
	
	return check_file(event->name);
}

int main(int argc, char* argv[])
{
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd < 0) {
        LOG_ERROR("inofity_init1: Failed");
    }

    int watched_fd = inotify_add_watch(inotify_fd, WATCH_PATH, IN_ALL_EVENTS ^ IN_OPEN ^ IN_ACCESS ^ IN_CLOSE);
    if (watched_fd < 0) {
        close(inotify_fd);
        LOG_ERROR("inotify_add_watch: Failed");
	}

	char buffer[BUFSIZE];
	struct inotify_event* event = NULL;
	int i = 0;

	while (1) {
		ssize_t len = read(inotify_fd, buffer, sizeof(buffer));
		if (len == -1 && errno != EAGAIN) {
			LOG_ERROR("read failed");
		}

        if (len < 0)
			continue;

		while (i < len) {
        	event = (struct inotify_event *)&buffer[i];

        	if (!event)
        		break;

			printf ("wd=%d mask=%x cookie=%u len=%u\n",
				event->wd, event->mask,
				event->cookie, event->len);

			if (event->len)
        		printf("event->name: %s\n", event->name);

			if (event->wd == watched_fd && !check_event(event)) {
                unlink(event->name);
                printf("file %s was deleted\n", event->name);
            }
        		

        	i += sizeof(struct inotify_event) + event->len;
		}

		i = 0;
		memset(buffer, 0, BUFSIZE);
		event = NULL;
        
	}

    close(inotify_fd);
    return 0;
}
