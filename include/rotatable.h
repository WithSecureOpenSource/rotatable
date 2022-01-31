#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dynamic rotation parameters */
typedef struct {
    uid_t uid;
    gid_t gid;
    int max_files;     /* the maximum number of rotated files */
    int max_seconds;   /* the maximum age of rotated files */
    int64_t max_bytes; /* the maximum cumulative size of rotated files */
} rotatable_params_t;

typedef struct rotatable rotatable_t;

/* Create a rotatable object to manage (log) file rotation. The given
 * arguments are stored with the object but no file is created
 * immediately.
 *
 * Right after calling make_rotatable(), the application can
 * optionally call rotatable_set_mode() and rotatable_rename().
 *
 * Whenever it needs to produce output to the log file, the
 * application must first call rotatable_rotate_maybe(). If the call
 * succeeds, the application should then call rotatable_file() to get
 * an open file handle and write to it normally.
 *
 * Rotation is controlled using a set of parameters. Of these,
 * pathname_prefix, pathname_suffix and rotate_size are fixed. The
 * params structure supplies additional parameters, which may change
 * dynamically. They are explained below.
 *
 * Multiple rotatable objects in the same process or different
 * processes can refer to the same rotatable files. In that case, the
 * arguments to make_rotatable() should be the same. Notably, params
 * can be a shared object. Inter-process synchronization and
 * communication is not provided by the rotatable object. */
rotatable_t *make_rotatable(const char *pathname_prefix,
                            const char *pathname_suffix, ssize_t rotate_size,
                            const rotatable_params_t *params);

/* Rotatable files are created with 0666 & ~umask by default. This
 * function changes the default mode from 0666 to something else. The
 * umask still affects the permissions in the usual way.
 *
 * You should call this function right after calling
 * make_rotatable(). */
void rotatable_set_mode(rotatable_t *rot, mode_t mode);

/* Destroy the rotatable object and close any possible open files. */
void destroy_rotatable(rotatable_t *rot);

/* Return an open file handle the application should write to. You
 * must call rotatable_rotate_maybe() successfully at least once
 * (typically, every time) before calling rotatable_file().
 *
 * The application should call fflush(3) after writing to the file. */
FILE *rotatable_file(rotatable_t *rot);

/* Try to rename a preexisting (log) file according to the rotation
 * rules. This function is typically called when the application
 * starts so new log entries go to an empty file.
 *
 * The pathname of the current log file is
 *
 *    pathname_prefix @ pathname_suffix
 *
 * where "@" stands for string concatenation. The given timestamp is
 * used to form the new pathname as follows:
 *
 *    pathname_prefix @ "-" @
 *        YYYYMMDD @ "-" @ hhmmss @ "." @ uuuuuu @
 *        pathname_suffix
 *
 * If the rename operation fails (for example, the current log file
 * does not exist), rotatable_rename() returns false.
 *
 * Otherwise, rotatable_rename() checks the rotation limits. If they
 * are exceeded, rotatable_rename() removes oldest rotated files as
 * necessary to comply with the limits again:
 *
 * - If params->max_seconds >= 0, any rotated files whose st_mtim is
 *   more than params->max_seconds old are removed.
 *
 * - If params->max_files >= 0, oldest rotated files are removed until
 *   the total rotated file count is <= params->max_files.
 *
 * - If params->max_bytes >= 0, oldest rotated files are removed until
 *   the sum of their sizes is <= params->max_bytes.
 *
 * Then, regardless of the success of the removals, true is returned. */
bool rotatable_rename(rotatable_t *rot, const struct tm *tm, int usec);

typedef enum {
    ROTATION_FAIL,
    ROTATION_OK,
    ROTATION_ROTATED,
} rotation_result_t;

/* Prepare to write into the (log) file. If the function returns
 * ROTATION_FAIL, some I/O error (see errno) has prevented the
 * operation and no output is possible.
 *
 * If the function returns ROTATION_OK or ROTATION_ROTATED, the file
 * is ready for output. The application should use rotatable_file() to
 * get a handle to the open file.
 *
 * ROTATION_ROTATED indicates that file rotation has taken place. That
 * occurs if rotate_size >= 0 and the current file is already larger
 * than that size.
 *
 * The force_reopen argument causes the underlying file handle to be
 * closed and reopened, which otherwise only happens during rotation.
 * The argument can be used when multiple rotatable objects (in
 * multiple processes, for example) share the same pathname prefix
 * (and, typically, parameters). If one process finds out (somehow) a
 * sibling process has performed rotation, force_reopen should be set
 * to true. Inter-process synchronization and communication is not
 * provided by the rotatable object. */
rotation_result_t rotatable_rotate_maybe(rotatable_t *rot, const struct tm *tm,
                                         int usec, bool force_reopen);

/* Call rotatable_invalidate() if there is a chance you may have
 * closed the underlying file descriptor of the rotatable object. That
 * could happen after you categorically close all open file descriptor
 * after a call to fork(), for example. */
void rotatable_invalidate(rotatable_t *rot);

#ifdef __cplusplus
}
#endif
