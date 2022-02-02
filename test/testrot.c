#include "testrot.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <fsdyn/charstr.h>
#include <fsdyn/date.h>
#include <fsdyn/fsalloc.h>
#include <rotatable/rotatable.h>

static int failures = 0;

static void timestamp(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec;
    struct tm tm;
    gmtime_r(&t, &tm);
    char s[50];
    strftime(s, sizeof s, "%F %T", &tm);
    fprintf(stderr, "%s.%03d: ", s, (int) (tv.tv_usec / 1000));
}

void tlog(const char *format, ...)
{
    timestamp();
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static int outstanding_object_count = 0;
static bool log_allocation = false; /* set in debugger */

static fs_realloc_t reallocator;

static void *test_realloc(void *ptr, size_t size)
{
    void *obj = (*reallocator)(ptr, size);
    if (obj == NULL && size != 0)
        assert(0);
    if (ptr != NULL) {
        outstanding_object_count--;
        if (log_allocation)
            tlog("free %p", ptr);
    }
    if (obj != NULL) {
        outstanding_object_count++;
        if (log_allocation)
            tlog("alloc %p", obj);
    }
    return obj;
}

int posttest_check(int tentative_verdict)
{
    if (tentative_verdict != PASS)
        return tentative_verdict;
    if (outstanding_object_count != 0) {
        tlog("Garbage generated");
        return FAIL;
    }
    return PASS;
}

static void verify(const char *name, VERDICT (*testcase)(void))
{
    tlog("Begin %s", name);
    switch (testcase()) {
        case PASS:
            tlog("PASS");
            break;
        case FAIL:
            tlog("FAIL");
            failures++;
            break;
        default:
            assert(0);
    }
    tlog("End %s", name);
}

static bool empty_dir(const char *path)
{
    DIR *dir = opendir(path);
    for (;;) {
        struct dirent *ent = readdir(dir);
        if (!ent) {
            closedir(dir);
            return true;
        }
        if (strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..")) {
            closedir(dir);
            return false;
        }
    }
}

static bool contents_equal(const char *path, const char *contents)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    size_t size = strlen(contents);
    char buffer[size + 1];
    ssize_t count = read(fd, buffer, size + 1);
    close(fd);
    if (count != (ssize_t) size)
        return false;
    buffer[size] = '\0';
    return !strcmp(contents, buffer);
}

static int now(struct tm *tm)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    epoch_to_utc(tv.tv_sec, tm);
    return tv.tv_usec;
}

static FILE *rotate_maybe(rotatable_t *rot, const char *tag,
                          rotation_result_t expected, bool force_reopen)
{
    struct tm tm;
    switch (rotatable_rotate_maybe(rot, &tm, now(&tm), force_reopen)) {
        case ROTATION_FAIL:
            tlog("%s: ROTATION_FAIL unexpectedly (errno=%d)", tag, errno);
            return NULL;
        case ROTATION_OK:
            if (expected != ROTATION_OK) {
                tlog("%s: ROTATION_OK unexpectedly", tag);
                return NULL;
            }
            break;
        case ROTATION_ROTATED:
            if (expected != ROTATION_ROTATED) {
                tlog("%s: ROTATION_ROTATED unexpectedly", tag);
                return NULL;
            }
            break;
        default:
            assert(false);
    }
    FILE *rotf = rotatable_file(rot);
    if (!rotf)
        tlog("%s: rotatable_file() returned NULL", tag);
    return rotf;
}

static bool write_entry(rotatable_t *rot, const char *tag,
                        rotation_result_t expected, bool force_reopen,
                        const char *format, ...)
{
    FILE *rotf = rotate_maybe(rot, tag, expected, force_reopen);
    if (!rotf)
        return false;
    va_list ap;
    va_start(ap, format);
    vfprintf(rotf, format, ap);
    va_end(ap);
    fflush(rotf);
    return true;
}

static bool rename_rot(rotatable_t *rot)
{
    struct tm tm;
    return rotatable_rename(rot, &tm, now(&tm));
}

static int get_mode(const char *path)
{
    struct stat statbuf;
    int status = stat(path, &statbuf);
    assert(status >= 0);
    return statbuf.st_mode & ALLPERMS;
}

#define VERIFY(tc) verify(#tc, tc)

static char *log_path;

VERDICT test_basic(void)
{
    char *tc_dir = charstr_printf("%s/basic", log_path);
    (void) mkdir(tc_dir, 0777);
    char *prefix = charstr_printf("%s/pfx", tc_dir);
    rotatable_params_t params = {
        .uid = geteuid(),
        .gid = getegid(),
        .max_files = -1,
        .max_seconds = -1,
        .max_bytes = 100 * 1000,
    };
    rotatable_t *rot = make_rotatable(prefix, ".log", 1000, &params);
    if (!empty_dir(tc_dir)) {
        tlog("basic: directory not empty after make_rotatable()");
        goto fail;
    }
    for (int i = 0; i < 4; i++)
        if (!write_entry(rot, "basic", ROTATION_OK, false, "testing %d\n", i))
            goto fail;
    char *path = charstr_printf("%s.log", prefix);
    if (!contents_equal(path, "testing 0\ntesting 1\ntesting 2\ntesting 3\n")) {
        tlog("basic: bad initial contents");
        fsfree(path);
        goto fail;
    }
    destroy_rotatable(rot);
    bool equal =
        contents_equal(path, "testing 0\ntesting 1\ntesting 2\ntesting 3\n");
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    if (!equal) {
        tlog("basic: bad final contents");
        return FAIL;
    }
    return posttest_check(PASS);

fail:
    destroy_rotatable(rot);
    fsfree(prefix);
    fsfree(tc_dir);
    return FAIL;
}

VERDICT test_mode(void)
{
    char *tc_dir = charstr_printf("%s/mode", log_path);
    (void) mkdir(tc_dir, 0777);
    char *prefix = charstr_printf("%s/pfx", tc_dir);
    char *path = charstr_printf("%s.log", prefix);
    rotatable_params_t params = {
        .uid = geteuid(),
        .gid = getegid(),
        .max_files = -1,
        .max_seconds = -1,
        .max_bytes = 100 * 1000,
    };
    rotatable_t *rot = make_rotatable(prefix, ".log", 1000, &params);
    mode_t old_mode = umask(0002);
    FILE *rotf = rotate_maybe(rot, "mode", ROTATION_OK, false);
    if (!rotf)
        goto fail;
    if (get_mode(path) != 0664) {
        tlog("mode: 0664 expected");
        goto fail;
    }
    destroy_rotatable(rot);
    rot = make_rotatable(prefix, ".log", 1000, &params);
    rename_rot(rot);
    (void) umask(0007);
    rotf = rotate_maybe(rot, "mode", ROTATION_OK, false);
    if (!rotf)
        goto fail;
    if (get_mode(path) != 0660) {
        tlog("mode: 0660 expected");
        goto fail;
    }
    destroy_rotatable(rot);
    rot = make_rotatable(prefix, ".log", 1000, &params);
    rename_rot(rot);
    (void) umask(0477);
    rotf = rotate_maybe(rot, "mode", ROTATION_OK, false);
    if (!rotf)
        goto fail;
    if (get_mode(path) != 0200) {
        tlog("mode: 0200 expected");
        goto fail;
    }
    destroy_rotatable(rot);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    umask(old_mode);
    return posttest_check(PASS);

fail:
    destroy_rotatable(rot);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    umask(old_mode);
    return FAIL;
}

static char *normalize_name(const char *name)
{
    char *normal = charstr_dupstr(name);
    for (char *p = normal; *p; p++)
        if (charstr_char_class(*p) & CHARSTR_DIGIT)
            *p = '9';
    return normal;
}

static bool check_rotation(const char *tc_dir, const char *path,
                           const char *start_name, const char *end_name,
                           int countdown)
{
    DIR *dir = opendir(tc_dir);
    for (;;) {
        struct dirent *ent = readdir(dir);
        if (!ent) {
            if (countdown) {
                tlog("rotation: unexpected file count");
                return false;
            }
            break;
        }
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
            continue;
        countdown--;
        if (!strcmp(ent->d_name, "pfx.log")) {
            if (!contents_equal(path, "some fleeting sample\n")) {
                tlog("basic: bad %s contents", ent->d_name);
                closedir(dir);
                return false;
            }
            continue;
        }
        char *normal = normalize_name(ent->d_name);
        if (strcmp(normal, "pfx-99999999-999999.999999.log")) {
            tlog("rotation: abnormal pathname (%s)", ent->d_name);
            closedir(dir);
            fsfree(normal);
            return false;
        }
        fsfree(normal);
        if (strcmp(ent->d_name, start_name) < 0 ||
            strcmp(ent->d_name, end_name) > 0) {
            tlog("rotation: unexpected pathname (%s)", ent->d_name);
            closedir(dir);
            return false;
        }
        char *ent_path = charstr_printf("%s/%s", tc_dir, ent->d_name);
        if (!contents_equal(ent_path,
                            "some fleeting sample\n"
                            "some fleeting sample\n")) {
            tlog("basic: bad %s contents", ent->d_name);
            closedir(dir);
            fsfree(ent_path);
            return false;
        }
        fsfree(ent_path);
    }
    closedir(dir);
    return true;
}

static char *make_timestamp()
{
    struct tm tm;
    int us = now(&tm);
    return charstr_printf("pfx-%04d%02d%02d-%02d%02d%02d.%06d.log",
                          tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                          tm.tm_hour, tm.tm_min, tm.tm_sec, us);
}

VERDICT test_rotation(void)
{
    char *tc_dir = charstr_printf("%s/rotation", log_path);
    (void) mkdir(tc_dir, 0777);
    char *prefix = charstr_printf("%s/pfx", tc_dir);
    char *path = charstr_printf("%s.log", prefix);
    char *start_name = make_timestamp();
    char *end_name = NULL;
    rotatable_params_t params = {
        .uid = geteuid(),
        .gid = getegid(),
        .max_files = -1,
        .max_seconds = -1,
        .max_bytes = 100 * 1000,
    };
    rotatable_t *rot = make_rotatable(prefix, ".log", 40, &params);
    if (!write_entry(rot, "rotation", ROTATION_OK, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "rotation", ROTATION_OK, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "rotation", ROTATION_ROTATED, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "rotation", ROTATION_OK, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "rotation", ROTATION_ROTATED, false,
                     "some fleeting sample\n"))
        goto fail;
    end_name = make_timestamp();
    if (!check_rotation(tc_dir, path, start_name, end_name, 3))
        goto fail;
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return posttest_check(PASS);

fail:
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return FAIL;
}

VERDICT test_invalidation(void)
{
    char *tc_dir = charstr_printf("%s/invalidation", log_path);
    (void) mkdir(tc_dir, 0777);
    char *prefix = charstr_printf("%s/pfx", tc_dir);
    char *path = charstr_printf("%s.log", prefix);
    rotatable_params_t params = {
        .uid = geteuid(),
        .gid = getegid(),
        .max_files = -1,
        .max_seconds = -1,
        .max_bytes = 100 * 1000,
    };
    rotatable_t *rot = make_rotatable(prefix, ".log", 1000, &params);
    if (!write_entry(rot, "invalidation", ROTATION_OK, false, "text\n") ||
        !write_entry(rot, "invalidation", ROTATION_OK, false, "text\n"))
        goto fail;
    FILE *rotf = rotate_maybe(rot, "invalidation", ROTATION_OK, false);
    if (!rotf)
        goto fail;
    fprintf(rotf, "text\n");
    fflush(rotf);
    close(fileno(rotf));
    rotatable_invalidate(rot);
    if (!write_entry(rot, "invalidation", ROTATION_OK, false, "text\n") ||
        !write_entry(rot, "invalidation", ROTATION_OK, false, "text\n"))
        goto fail;
    if (!contents_equal(path, "text\ntext\ntext\ntext\ntext\n")) {
        tlog("invalidation: contents");
        goto fail;
    }
    destroy_rotatable(rot);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return posttest_check(PASS);

fail:
    destroy_rotatable(rot);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return FAIL;
}

VERDICT test_params_files(void)
{
    char *tc_dir = charstr_printf("%s/params-files", log_path);
    (void) mkdir(tc_dir, 0777);
    char *prefix = charstr_printf("%s/pfx", tc_dir);
    char *path = charstr_printf("%s.log", prefix);
    char *start_name = NULL;
    char *end_name = NULL;
    enum { MAX_FILES = 2 };
    rotatable_params_t params = {
        .uid = geteuid(),
        .gid = getegid(),
        .max_files = MAX_FILES,
        .max_seconds = -1,
        .max_bytes = -1,
    };
    rotatable_t *rot = make_rotatable(prefix, ".log", 40, &params);
    if (!write_entry(rot, "params-files", ROTATION_OK, false,
                     "some fleeting sample\n"))
        goto fail;
    enum { N = 100 };
    for (int i = 0; i < N; i++)
        if (!write_entry(rot, "params-files", ROTATION_OK, false,
                         "some fleeting sample\n") ||
            !write_entry(rot, "params-files", ROTATION_ROTATED, false,
                         "some fleeting sample\n"))
            goto fail;
    start_name = make_timestamp();
    if (!write_entry(rot, "params-files", ROTATION_OK, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "params-files", ROTATION_ROTATED, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "params-files", ROTATION_OK, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "params-files", ROTATION_ROTATED, false,
                     "some fleeting sample\n"))
        goto fail;
    end_name = make_timestamp();
    if (!check_rotation(tc_dir, path, start_name, end_name, MAX_FILES + 1))
        goto fail;
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return posttest_check(PASS);

fail:
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return FAIL;
}

VERDICT test_params_seconds(void)
{
    char *tc_dir = charstr_printf("%s/params-seconds", log_path);
    (void) mkdir(tc_dir, 0777);
    char *prefix = charstr_printf("%s/pfx", tc_dir);
    char *path = charstr_printf("%s.log", prefix);
    char *start_name = NULL;
    char *end_name = NULL;
    rotatable_params_t params = {
        .uid = geteuid(),
        .gid = getegid(),
        .max_files = 10,
        .max_seconds = 2,
        .max_bytes = 1000,
    };
    rotatable_t *rot = make_rotatable(prefix, ".log", 40, &params);
    if (!write_entry(rot, "params-seconds", ROTATION_OK, false,
                     "some fleeting sample\n"))
        goto fail;
    enum { N = 100 };
    for (int i = 0; i < N; i++)
        if (!write_entry(rot, "params-seconds", ROTATION_OK, false,
                         "some fleeting sample\n") ||
            !write_entry(rot, "params-seconds", ROTATION_ROTATED, false,
                         "some fleeting sample\n"))
            goto fail;
    start_name = make_timestamp();
    if (!write_entry(rot, "params-seconds", ROTATION_OK, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "params-seconds", ROTATION_ROTATED, false,
                     "some fleeting sample\n"))
        goto fail;
    sleep(2);
    if (!write_entry(rot, "params-seconds", ROTATION_OK, false,
                     "some fleeting sample\n"))
        goto fail;
    sleep(1);
    if (!write_entry(rot, "params-seconds", ROTATION_ROTATED, false,
                     "some fleeting sample\n"))
        goto fail;
    end_name = make_timestamp();
    if (!check_rotation(tc_dir, path, start_name, end_name, 3))
        goto fail;
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return posttest_check(PASS);

fail:
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return FAIL;
}

VERDICT test_params_bytes(void)
{
    char *tc_dir = charstr_printf("%s/params-bytes", log_path);
    (void) mkdir(tc_dir, 0777);
    char *prefix = charstr_printf("%s/pfx", tc_dir);
    char *path = charstr_printf("%s.log", prefix);
    char *start_name = NULL;
    char *end_name = NULL;
    rotatable_params_t params = {
        .uid = geteuid(),
        .gid = getegid(),
        .max_files = -1,
        .max_seconds = -1,
        .max_bytes = 75,
    };
    rotatable_t *rot = make_rotatable(prefix, ".log", 40, &params);
    if (!write_entry(rot, "params-files", ROTATION_OK, false,
                     "some fleeting sample\n"))
        goto fail;
    enum { N = 100 };
    for (int i = 0; i < N; i++)
        if (!write_entry(rot, "params-files", ROTATION_OK, false,
                         "some fleeting sample\n") ||
            !write_entry(rot, "params-files", ROTATION_ROTATED, false,
                         "some fleeting sample\n"))
            goto fail;
    start_name = make_timestamp();
    if (!write_entry(rot, "params-files", ROTATION_OK, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "params-files", ROTATION_ROTATED, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "params-files", ROTATION_OK, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "params-files", ROTATION_ROTATED, false,
                     "some fleeting sample\n"))
        goto fail;
    end_name = make_timestamp();
    if (!check_rotation(tc_dir, path, start_name, end_name, 3))
        goto fail;
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return posttest_check(PASS);

fail:
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return FAIL;
}

VERDICT test_params_unlimited(void)
{
    char *tc_dir = charstr_printf("%s/params-unlimited", log_path);
    (void) mkdir(tc_dir, 0777);
    char *prefix = charstr_printf("%s/pfx", tc_dir);
    char *path = charstr_printf("%s.log", prefix);
    char *start_name = make_timestamp();
    char *end_name = NULL;
    rotatable_params_t params = {
        .uid = geteuid(),
        .gid = getegid(),
        .max_files = -1,
        .max_seconds = -1,
        .max_bytes = -1,
    };
    rotatable_t *rot = make_rotatable(prefix, ".log", 40, &params);
    if (!write_entry(rot, "params-unlimited", ROTATION_OK, false,
                     "some fleeting sample\n"))
        goto fail;
    enum { N = 100 };
    for (int i = 0; i < N; i++)
        if (!write_entry(rot, "params-unlimited", ROTATION_OK, false,
                         "some fleeting sample\n") ||
            !write_entry(rot, "params-unlimited", ROTATION_ROTATED, false,
                         "some fleeting sample\n"))
            goto fail;
    end_name = make_timestamp();
    if (!check_rotation(tc_dir, path, start_name, end_name, N + 1))
        goto fail;
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return posttest_check(PASS);

fail:
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return FAIL;
}

VERDICT test_force_reopen(void)
{
    char *tc_dir = charstr_printf("%s/force-reopen", log_path);
    (void) mkdir(tc_dir, 0777);
    char *prefix = charstr_printf("%s/pfx", tc_dir);
    char *path = charstr_printf("%s.log", prefix);
    char *start_name = make_timestamp();
    char *end_name = NULL;
    rotatable_params_t params = {
        .uid = geteuid(),
        .gid = getegid(),
        .max_files = -1,
        .max_seconds = -1,
        .max_bytes = 100 * 1000,
    };
    rotatable_t *rot = make_rotatable(prefix, ".log", 40, &params);
    if (!write_entry(rot, "force-reopen", ROTATION_OK, true,
                     "some fleeting sample\n") ||
        !write_entry(rot, "force-reopen", ROTATION_OK, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "force-reopen", ROTATION_ROTATED, true,
                     "some fleeting sample\n") ||
        !write_entry(rot, "force-reopen", ROTATION_OK, false,
                     "some fleeting sample\n") ||
        !write_entry(rot, "force-reopen", ROTATION_ROTATED, true,
                     "some fleeting sample\n"))
        goto fail;
    end_name = make_timestamp();
    if (!check_rotation(tc_dir, path, start_name, end_name, 3))
        goto fail;
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return posttest_check(PASS);

fail:
    destroy_rotatable(rot);
    fsfree(start_name);
    fsfree(end_name);
    fsfree(path);
    fsfree(prefix);
    fsfree(tc_dir);
    return FAIL;
}

int main(int argc, char *const argv[])
{
    if (argc != 2 || argv[1][0] == '-') {
        fprintf(stderr, "Usage: %s directory\n", argv[0]);
        return 1;
    }
    log_path = charstr_printf("%s/log", argv[1]);
    tlog("Log path: %s", log_path);
    (void) mkdir(log_path, 0777);
    struct stat statbuf;
    stat(log_path, &statbuf);
    assert(S_ISDIR(statbuf.st_mode));
    reallocator = fs_get_reallocator();
    fs_set_reallocator(test_realloc);
    VERIFY(test_basic);
    VERIFY(test_mode);
    VERIFY(test_rotation);
    VERIFY(test_invalidation);
    VERIFY(test_params_files);
    VERIFY(test_params_seconds);
    VERIFY(test_params_bytes);
    VERIFY(test_params_unlimited);
    VERIFY(test_force_reopen);
    fsfree(log_path);
    return failures;
}
