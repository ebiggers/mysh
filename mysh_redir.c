/*
 * mysh_redir.c
 *
 * Handles command redirections
 */

#include "mysh.h"
#include <unistd.h>
#include <fcntl.h>

int undo_redirections(const struct orig_fds *orig)
{
	int ret = 0;
	int i;
	for (i = 0; i < ARRAY_SIZE(orig->fds); i++) {
		if (orig->fds[i] >= 0) {
			if (dup2(orig->fds[i], i) < 0)
				ret = -1;
			if (close(orig->fds[i]) < 0)
				ret = -1;
		}
	}
	return ret;
}

/* Apply the redirections in the list @redirs.  If @orig is non-NULL, save the
 * original file descriptors in there. */
int do_redirections(const struct list_head *redirs, struct orig_fds *orig)
{
	int i;
	int ret;
	struct redirection *redir;

	if (orig)
		for (i = 0; i < ARRAY_SIZE(orig->fds); i++)
			orig->fds[i] = -1;
	list_for_each_entry(redir, redirs, list) {
		int src_fd;
		if (redir->is_file) {
			src_fd = open(redir->src_filename, redir->open_flags, 0666);
			if (src_fd < 0) {
				mysh_error_with_errno("can't open %s for %s",
						      redir->src_filename,
						      (redir->open_flags & O_WRONLY)
						      ? "writing" : "reading");
				ret = -1;
				goto out_undo_redirections;
			}
		} else {
			src_fd = redir->src_fd;
		}

		if (orig &&
		    redir->dest_fd < ARRAY_SIZE(orig->fds) &&
		    orig->fds[redir->dest_fd] < 0)
		{
			ret = dup(redir->dest_fd);
			if (ret < 0)
				goto out_undo_redirections;
			orig->fds[redir->dest_fd] = ret;
		}
		ret = dup2(src_fd, redir->dest_fd);
		if (redir->is_file)
			close(src_fd);
		if (ret < 0) {
			mysh_error_with_errno("can't perform redirection");
			goto out_undo_redirections;
		}
	}
	ret = 0;
	goto out;
out_undo_redirections:
	if (orig)
		(void)undo_redirections(orig);
out:
	return ret;
}
