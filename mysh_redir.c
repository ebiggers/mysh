#include "mysh.h"
#include <unistd.h>
#include <fcntl.h>

int undo_redirections(const struct orig_fds *orig)
{
	int ret = 0;
	if (orig->orig_stdin >= 0)
		if (dup2(orig->orig_stdin, STDIN_FILENO) < 0)
			ret = -1;
	if (orig->orig_stdout >= 0)
		if (dup2(orig->orig_stdout, STDOUT_FILENO) < 0)
			ret = -1;
	return ret;
}

/* Apply the redirections in the token list @redirs.  If @orig is non-NULL, save
 * the original file descriptors in there.  Return %true on success, %false on
 * failure. */
int do_redirections(const struct token *redirs, struct orig_fds *orig)
{
	while (redirs && (redirs->type & TOK_CLASS_REDIRECTION)) {
		int open_flags;
		int dest_fd;
		int *orig_fd_p = NULL;
		int ret;
		int fd;
		const char *filename;

		if (redirs->type == TOK_STDIN_REDIRECTION) {
			open_flags = O_RDONLY;
			dest_fd = STDIN_FILENO;
			if (orig)
				orig_fd_p = &orig->orig_stdin;
		} else {
			open_flags = O_WRONLY | O_TRUNC | O_CREAT;
			dest_fd = STDOUT_FILENO;
			if (orig)
				orig_fd_p = &orig->orig_stdout;
		}

		if (orig_fd_p != NULL && *orig_fd_p < 0) {
			*orig_fd_p = dup(dest_fd);
			if (*orig_fd_p < 0) {
				mysh_error_with_errno("Failed to duplicate "
						      "file descriptor %d", dest_fd);
				goto out_undo_redirections;
			}
		}

		redirs = redirs->next;
		filename = redirs->tok_data;
		redirs = redirs->next;
		fd = open(filename, open_flags, 0666);
		if (fd < 0) {
			mysh_error_with_errno("can't open %s", filename);
			goto out_undo_redirections;
		}
		ret = dup2(fd, dest_fd);
		close(fd);
		if (ret < 0) {
			mysh_error_with_errno("can't perform redirection to or from %s",
					      filename);
			goto out_undo_redirections;
		}
	}
	return 0;
out_undo_redirections:
	if (orig)
		(void)undo_redirections(orig);
	return -1;
}
