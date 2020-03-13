#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

/* Dynamic rotation parameters */
typedef struct {
    uid_t uid;
    gid_t gid;
    int max_files;
    int max_seconds;
    int64_t max_bytes;
} rotatable_params_t;

typedef struct rotatable rotatable_t;

rotatable_t *make_rotatable(const char *pathname_prefix,
                            const char *pathname_suffix,
                            ssize_t rotate_size,
                            const rotatable_params_t *params);

/* Rotatable files are created with 0666 & ~umask by default. This
 * function changes the default mode from 0666 to something else. The
 * umask still affects the permissions in the usual way.
 *
 * You should call this function right after calling
 * make_rotatable(). */
void rotatable_set_mode(rotatable_t *rot, mode_t mode);

void destroy_rotatable(rotatable_t *rot);
FILE *rotatable_file(rotatable_t *rot);
bool rotatable_rename(rotatable_t *rot, const struct tm *tm, int usec);

typedef enum {
    ROTATION_FAIL,
    ROTATION_OK,
    ROTATION_ROTATED
} rotation_result_t;

rotation_result_t rotatable_rotate_maybe(rotatable_t *rot,
                                         const struct tm *tm, int usec,
                                         bool force_reopen);

/* Call rotatable_invalidate() if there is a chance you may have
 * closed the underlying file descriptor of the rotatable object. That
 * could happen after you categorically close all open file descriptor
 * after a call to fork(), for example. */
void rotatable_invalidate(rotatable_t *rot);
