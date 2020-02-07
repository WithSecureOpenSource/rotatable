#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fsdyn/fsalloc.h>
#include <fsdyn/charstr.h>
#include "rotatable.h"

struct rotatable {
    FILE *outf;
    char *pathname_prefix;
    char *pathname_suffix;
    char *pathname;
    ssize_t rotate_size;
    const rotatable_params_t *params;
};

#define NS_IN_S 1000000000LL

rotatable_t *make_rotatable(const char *pathname_prefix,
                            const char *pathname_suffix,
                            ssize_t rotate_size,
                            const rotatable_params_t *params)
{
    rotatable_t *rot = fsalloc(sizeof *rot);
    rot->pathname_prefix = charstr_dupstr(pathname_prefix);
    rot->pathname_suffix = charstr_dupstr(pathname_suffix);
    rot->pathname = charstr_printf("%s%s", pathname_prefix, pathname_suffix);
    rot->rotate_size = rotate_size;
    rot->params = params;
    rot->outf = NULL;
    return rot;
}

void destroy_rotatable(rotatable_t *rot)
{
    if (rot->outf)
        fclose(rot->outf);
    fsfree(rot->pathname_prefix);
    fsfree(rot->pathname_suffix);
    fsfree(rot->pathname);
    fsfree(rot);
}

FILE *rotatable_file(rotatable_t *rot)
{
    return rot->outf;
}

static bool is_rotated_file(const char *file_prefix, const char *file_suffix,
                            const char *file_name)
{
    const char *p = file_prefix, *q = file_name;
    while (*p && *p == *q)
        p++, q++;
    if (*p)
        return false;
    p = "-####-##-##T##:##:##.######"; /* infix template */
    while (*p && (*p == '#' || *p == *q))
        p++, q++;
    if (*p)
        return false;
    p = file_suffix;
    while (*p && *p == *q)
        p++, q++;
    return !*p && !*q;
}

struct fileinfo {
    char *pathname;
    off_t size;
    uint64_t mtime;             /* epoch nanoseconds */
};

/* Return the pathnames of rotated trace log files. The number of
 * elements in the array is returned in *pcount. Free the returned array
 * with fsfree() after use. Also, free each of the 'pathname' entries of
 * the array elements.
 *
 * The size and mtime values are unused.
 *
 * The array elements are not in any particular order.
 */
static struct fileinfo *find_rot_files(const char *pathname_prefix,
                                       const char *pathname_suffix,
                                       int *pcount)
{
    char *dirname;
    const char *slash = strrchr(pathname_prefix, '/');
    const char *file_prefix;
    if (slash == NULL) {
        dirname = charstr_dupstr(".");
        file_prefix = pathname_prefix;
    } else {
        dirname = charstr_dupsubstr(pathname_prefix, slash);
        file_prefix = slash + 1;
    }
    DIR *dir = opendir(dirname);
    struct fileinfo *info = NULL;
    *pcount = 0;
    if (dir) {
        for (;;) {
            struct dirent *entry = readdir(dir);
            if (entry == NULL)
                break;
            if (is_rotated_file(file_prefix, pathname_suffix, entry->d_name)) {
                char *pathname =
                    charstr_printf("%s/%s", dirname, entry->d_name);
                ++*pcount;
                info = fsrealloc(info, *pcount * sizeof *info);
                info[*pcount - 1].pathname = pathname;
            }
        }
        closedir(dir);
    }
    fsfree(dirname);
    return info;
}

static uint64_t stat_timestamp(struct stat *statbuf)
{
#ifdef __linux__
    return statbuf->st_mtim.tv_sec * NS_IN_S + statbuf->st_mtim.tv_nsec;
#else
    return statbuf->st_mtimespec.tv_sec * NS_IN_S +
        statbuf->st_mtimespec.tv_nsec;
#endif
}

/*
 * Fill in the stat info for each pathnam inside the struct fileinfo
 * structures.
 *
 * Return the total byte count.
 */
static uint64_t stat_files(struct fileinfo *info, int count)
{
    uint64_t total_bytes = 0;
    int i;
    for (i = 0; i < count; i++) {
        struct stat statbuf;
        if (stat(info[i].pathname, &statbuf) < 0) {
            /* Probably deleted. Choose nice values. */
            info[i].size = 0;
            info[i].mtime = 0;
        } else if (!S_ISREG(statbuf.st_mode)) {
            /* Maybe a soft link; feel free to try to remove it. */
            info[i].size = 0;
            info[i].mtime = stat_timestamp(&statbuf);
        } else {
            info[i].size = statbuf.st_size;
            info[i].mtime = stat_timestamp(&statbuf);
            total_bytes += statbuf.st_size;
        }
    }
    return total_bytes;
}

/*
 * Age order, older first.
 */
static int fileinfo_cmp(const void *arg1, const void *arg2)
{
    const struct fileinfo *i1 = arg1;
    const struct fileinfo *i2 = arg2;
    if (i1->mtime < i2->mtime)
        return -1;
    return i1->mtime > i2->mtime;
}

static void enforce_params(rotatable_t *rot)
{
    int count;
    struct fileinfo *info =
        find_rot_files(rot->pathname_prefix, rot->pathname_suffix, &count);
    uint64_t remaining_bytes = stat_files(info, count);
    qsort(info, count, sizeof *info, fileinfo_cmp);
    uint64_t cutoff_time;
    if (rot->params->max_seconds >= 0)
        cutoff_time = (time(NULL) - rot->params->max_seconds) * NS_IN_S;
    else cutoff_time = 0;
    int i;
    for (i = 0; i < count; i++)
        if ((rot->params->max_files < 0 ||
             count - i <= rot->params->max_files) &&
            info[i].mtime >= cutoff_time &&
            (rot->params->max_bytes < 0 ||
             remaining_bytes <= (uint64_t) rot->params->max_bytes))
            break;
        else remaining_bytes -= info[i].size;
    /* [i] now refers to the oldest trace log file that would still keep
     * us within the given params. The API spec calls for keeping those
     * files plus one more, so [i - 1] should be kept and older ones (if
     * any) removed. */
    int last_one_to_keep = i - 1;
    for (i = 0; i < last_one_to_keep; i++)
        (void) unlink(info[i].pathname); /* silently ignore errors */
    for (i = 0; i < count; i++)
        fsfree(info[i].pathname);
    fsfree(info);
}

bool rotatable_rename(rotatable_t *rot, const struct tm *tm, int usec)
{
    char *timed_pathname =
        charstr_printf("%s-%04d-%02d-%02dT%02d:%02d:%02d.%06d%s",
                       rot->pathname_prefix,
                       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                       tm->tm_hour, tm->tm_min, tm->tm_sec, usec,
                       rot->pathname_suffix);
    if (rename(rot->pathname, timed_pathname) < 0) {
        fsfree(timed_pathname);
        return false;
    }
    fsfree(timed_pathname);
    enforce_params(rot);
    return true;
}

static bool reopen(rotatable_t *rot)
{
    FILE *f = fopen(rot->pathname, "a");
    int err = errno;
    if (!f) {
        errno = err;
        return false;
    }
    if (fchown(fileno(f), rot->params->uid, rot->params->gid) < 0) {
        err = errno;
        fclose(f);
        errno = err;
        return false;
    }
    rot->outf = f;
    return true;
}

rotation_result_t rotatable_rotate_maybe(rotatable_t *rot, const struct tm *tm,
                                         int usec, bool force_reopen)
{
    if (!rot->outf) {
        if (!reopen(rot))
            return ROTATION_FAIL;
    } else if (force_reopen) {
        fclose(rot->outf);
        rot->outf = NULL;
        if (!reopen(rot))
            return ROTATION_FAIL;
    }
    if (rot->rotate_size < 0 || ftell(rot->outf) <= rot->rotate_size)
        return ROTATION_OK;
    fclose(rot->outf);
    rot->outf = NULL;
    if (!rotatable_rename(rot, tm, usec) || !reopen(rot))
        return ROTATION_FAIL;
    return ROTATION_ROTATED;
}

void rotatable_invalidate(rotatable_t *rot)
{
    if (rot->outf) {
        fclose(rot->outf);
        rot->outf = NULL;
    }
}
