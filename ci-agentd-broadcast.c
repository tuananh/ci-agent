#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "ci-agentd-broadcast.h"

static int set_cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD, 0);

	if (flags < 0)
		return -errno;

	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
		return -errno;

	return 0;
}

static int set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0)
		return -errno;

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -errno;

	return 0;
}

static int make_unix_listener(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -errno;

	set_cloexec(fd);
	set_nonblock(fd);

	unlink(path);

	struct sockaddr_un addr = {0};
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		int e = -errno;
		close(fd);
		return e;
	}

	chmod(path, 0666);

	if (listen(fd, SOMAXCONN) < 0)
	{
		int e = -errno;
		close(fd);
		return e;
	}

	return fd;
}

struct ci_agent_broadcaster {
	int listener_fd;
	int *fd_table;
	size_t fd_count;
	size_t fd_cap;
};

static int add_client(struct ci_agent_broadcaster *broadcaster, int new_fd)
{
	if (broadcaster == NULL)
		return -EINVAL;

	if (broadcaster->fd_count == broadcaster->fd_cap)
	{
		size_t new_cap = broadcaster->fd_cap != 0 ? broadcaster->fd_cap * 2 : 16;

		int *new_fdtable = reallocarray(broadcaster->fd_table, new_cap, sizeof(int));
		if (new_fdtable == NULL)
			return -ENOMEM;

		broadcaster->fd_table = new_fdtable;
		broadcaster->fd_cap = new_cap;
	}

	broadcaster->fd_table[broadcaster->fd_count++] = new_fd;

	return 0;
}

static void drop_client(struct ci_agent_broadcaster *broadcaster,
			size_t slot)
{
	if (broadcaster == NULL)
		return;

	if (broadcaster->fd_count > slot)
		return;

	close(broadcaster->fd_table[slot]);
	broadcaster->fd_table[slot] = broadcaster->fd_table[broadcaster->fd_count - 1];
	broadcaster->fd_count--;
}

int ci_agent_broadcaster_init(struct ci_agent_broadcaster **out,
				const char *listen_path)
{
	struct ci_agent_broadcaster *broadcaster;
	int listener_fd;

	listener_fd = make_unix_listener(listen_path);
	if (listener_fd < 0)
		return listener_fd;

	broadcaster = calloc(1, sizeof(*broadcaster));
	if (broadcaster == NULL)
		return -ENOMEM;

	broadcaster->listener_fd = listener_fd;
	*out = broadcaster;
	return 0;
}

void ci_agent_broadcaster_fini(struct ci_agent_broadcaster *broadcaster)
{
	if (broadcaster == NULL)
		return;

	for (size_t i = 0; i < broadcaster->fd_count; i++)
		drop_client(broadcaster, i);

	free(broadcaster->fd_table);
	free(broadcaster);
}

void ci_agent_broadcaster_send(struct ci_agent_broadcaster *broadcaster,
				 const char *buf, ...)
{
	char workbuf[8192];
	va_list va;
	size_t msgsize;

	va_start(va, buf);
	msgsize = vsnprintf(workbuf, sizeof workbuf, buf, va);
	va_end(va);

	for (size_t i = 0; i < broadcaster->fd_count; i++)
	{
		ssize_t written = send(broadcaster->fd_table[i], workbuf, msgsize, MSG_NOSIGNAL);

		/* error or incomplete write: drop the client */
		if (written != msgsize)
			drop_client(broadcaster, i);
	}
}

int ci_agent_broadcaster_fd(const struct ci_agent_broadcaster *broadcaster)
{
	if (broadcaster == NULL)
		return -EINVAL;

	return broadcaster->listener_fd;
}

int ci_agent_broadcaster_accept(struct ci_agent_broadcaster *broadcaster)
{
	if (broadcaster == NULL)
		return -EINVAL;

	int new_fd = accept(broadcaster->listener_fd, NULL, NULL);
	if (new_fd < 0)
		return -errno;

	set_cloexec(new_fd);
	set_nonblock(new_fd);

	if (add_client(broadcaster, new_fd) < 0)
	{
		close(new_fd);
		return -ENOMEM;
	}

	return 0;
}
