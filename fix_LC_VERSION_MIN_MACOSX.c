/*
 * I (asmaloney) got the original code from here and modified for my use:
 *
 *  https://gist.github.com/lynnlx/1c15f290383c750abdd9d42e70bd32e4
 *
 * It seems the original code is no longer available.
 *
 * Build it like this:
 *
 *  gcc fix_LC_VERSION_MIN_MACOSX.c -o fixMonoMinVersion
 *
 * The original code I had seems to be a modifed version of the code from here:
 *
 *  https://gist.github.com/landonf/1046134
 */

#include <stdio.h>
#include <libgen.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <mach-o/fat.h>
#include <mach-o/loader.h>

#define UNUSED(e, ...)          (void) ((void) (e), ##__VA_ARGS__)

#define LOG(fmt, ...)           (void) printf(fmt "\n", ##__VA_ARGS__)
#define LOG_STDERR(fmt, ...)    (void) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)       LOG_STDERR("[ERR] " fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)      LOG_STDERR("[WARN] " fmt, ##__VA_ARGS__)
#ifdef DEBUG
#define LOG_DBG(fmt, ...)       LOG("[DBG] " fmt, ##__VA_ARGS__)
#else
#define LOG_DBG(fmt, ...)       UNUSED(fmt, ##__VA_ARGS__)
#endif

#define assert_nonnull(p)       assert((p) != NULL)

#define set_goto(err, label)    do {        \
    e = (err);                              \
    goto label;                             \
} while (0)

typedef struct {
    void *data;
    size_t size;
} macho_buffer_t;

static void *macho_read(macho_buffer_t *buf, void *addr, size_t size)
{
    assert_nonnull(buf);
    assert_nonnull(addr);

    if (((uint8_t *) addr - (uint8_t *) buf->data) + size <= + buf->size)
        return addr;

    LOG_ERR("macho_read() fail  %zu vs %zu",
                (uint8_t *) addr - (uint8_t *) buf->data + size,
                buf->size);
    return NULL;
}

static void *macho_offset(
        macho_buffer_t *buf,
        void *addr,
        off_t off,
        size_t size)
{
    return macho_read(buf, ((uint8_t *) addr) + off, size);
}

static inline uint32_t macho_swap32(uint32_t i)
{
    return OSSwapInt32(i);
}

static inline uint32_t macho_nswap32(uint32_t i)
{
    return i;
}

static const char *mh_magic[] = {
    "magic", "cigam",
};

/**
 * @n       buffer size(at least 14 bytes)
 */
static int parse_ver(char *buf, size_t n, uint32_t v)
{
    assert_nonnull(buf);
    return snprintf(buf, n, "%u.%u.%u", v >> 16, (v >> 8) & 0xff, v & 0xff);
}

static uint32_t make_ver(uint16_t maj, uint8_t min, uint8_t fix)
{
    return maj << 16 | min << 8 | fix;
}

#define FMT_VER_STR     1

/**
 * Find LC_VERSION_MIN_MACOSX load command in a Mach-O executable
 * @return      0 if success -1 o.w.(errno will be set)
 */
static int find_LC_VERSION_MIN_MACOSX(macho_buffer_t *buf, int swap)
{
    uint32_t (*s32)(uint32_t) = swap ? macho_swap32 : macho_nswap32;
    struct mach_header *h;
    struct load_command *cmd;
    struct version_min_command *ver;
    off_t off;
    uint32_t i;

    h = macho_read(buf, buf->data, sizeof(*h));
    assert_nonnull(h);

    if (h->magic == MH_MAGIC_64 || h->magic == MH_CIGAM_64) {
        LOG_DBG("64-bit Mach-O %s", mh_magic[h->magic == MH_CIGAM_64]);
        off = sizeof(struct mach_header_64);
    } else {
        assert(h->magic == MH_MAGIC || h->magic == MH_CIGAM);
        LOG_DBG("32-bit Mach-O %s", mh_magic[h->magic == MH_CIGAM]);
        off = sizeof(struct mach_header);
    }

    for (i = 0; i < s32(h->ncmds); i++) {
        cmd = macho_offset(buf, buf->data, off, sizeof(*cmd));
        assert_nonnull(cmd);

        if (s32(cmd->cmd) != LC_VERSION_MIN_MACOSX) {
            off += s32(cmd->cmdsize);
            continue;
        }

        assert(s32(cmd->cmdsize) == sizeof(*ver));
        ver = macho_offset(buf, cmd, 0, sizeof(*ver));
        assert_nonnull(ver);

#if FMT_VER_STR
        char v1[16];
        char v2[16];
        (void) parse_ver(v1, sizeof(v1), ver->version);
        (void) parse_ver(v2, sizeof(v2), ver->sdk);
#endif

        LOG("Load command %u\n"
            "       cmd: %u LC_VERSION_MIN_MACOSX\n"
            "   cmdsize: %u\n"
#if FMT_VER_STR
            "   version: %s\n"
            "       sdk: %s\n",
            i, s32(ver->cmd), s32(ver->cmdsize), v1, v2);
#else
            "   version: %08x\n"
            "       sdk: %08x\n",
            i, s32(ver->cmd), s32(ver->cmdsize), ver->version, ver->sdk);
#endif

        if (ver->sdk < make_ver(10, 9, 0)) {
            LOG_WARN("the binary uses an SDK older than 10.9");
            ver->sdk = make_ver(10, 9, 0);
            LOG("updating to the 10.9 SDK");
        }

        break;
    }

    if (i == s32(h->ncmds)) {
        errno = ENOENT;
        return -1;
    }

    return 0;
}

static int parse_macho(macho_buffer_t *buf)
{
    assert_nonnull(buf);

    if (buf->size <= sizeof(struct mach_header)) {
        errno = ENOTSUP;
        return -1;
    }

    uint32_t *magic = macho_read(buf, buf->data, sizeof(*magic));
    assert_nonnull(magic);

    switch (*magic) {
    case MH_MAGIC:
    case MH_CIGAM:
    case MH_MAGIC_64:
    case MH_CIGAM_64: {
        int e;
        e = find_LC_VERSION_MIN_MACOSX(buf, *magic == MH_CIGAM || *magic == MH_CIGAM_64);
        if (e < 0) {
            LOG_ERR("find_LC_VERSION_MIN_MACOSX() fail  errno: %d", errno);
        }
        return e;
    }

    case FAT_MAGIC:
    case FAT_CIGAM: {
        struct fat_header *fh = macho_read(buf, buf->data, sizeof(*fh));
        assert_nonnull(fh);

        uint32_t nfat = OSSwapBigToHostInt32(fh->nfat_arch);
        LOG_DBG("%u architectures detected", nfat);

        struct fat_arch *fas = macho_offset(buf, fh, sizeof(*fh), sizeof(*fas));
        assert_nonnull(fas);

        uint32_t i;
        struct fat_arch *fa;
        for (i = 0; i < nfat; i++) {
            fa = macho_read(buf, fas + i, sizeof(*fa));
            assert_nonnull(fa);

            macho_buffer_t sub;
            sub.size = OSSwapBigToHostInt32(fa->size);
            sub.data = macho_offset(buf, buf->data, OSSwapBigToHostInt32(fa->offset), sub.size);
            assert_nonnull(sub.data);

            magic = macho_read(&sub, sub.data, sizeof(*magic));
            assert_nonnull(magic);

            LOG_DBG("Arch #%d magic: %#x", i, *magic);
            if (find_LC_VERSION_MIN_MACOSX(&sub, *magic == MH_CIGAM || *magic == MH_CIGAM_64) < 0) {
                LOG_ERR("find_LC_VERSION_MIN_MACOSX() fail  i: %u errno: %d", i, errno);
            }
        }

        break;
    }

    case FAT_MAGIC_64:
    case FAT_CIGAM_64:
        LOG_WARN("TODO: support 64-bit FAT header");
        break;

    default:
        LOG_ERR("Unknown Mach-O magic: %#08x", *magic);
        errno = EBADMACHO;
        return -1;
    }

    return 0;
}

/*
 * see: https://stackoverflow.com/questions/35859545/how-to-change-characters-in-a-text-file-using-cs-mmap
 */
static int parse_preflight(const char *path)
{
    int e = 0;
    int fd;
    struct stat st;
    void *data;
    macho_buffer_t buf;

    assert_nonnull(path);

    fd = open(path, O_RDWR);
    if (fd < 0) {
        LOG_ERR("open(2) fail  path: %s errno: %d", path, errno);
        set_goto(-1, out_exit);
    }

    if (fstat(fd, &st) < 0) {
        LOG_ERR("fstat(2) fail  path: %s fd: %d errno: %d", path, fd, errno);
        set_goto(-1, out_close);
    } else if (!S_ISREG(st.st_mode)) {
        LOG_ERR("path %s isn't regular file", path);
        errno = ENOTSUP;
        set_goto(-1, out_close);
    }

    data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
    if (data == NULL) {
        LOG_ERR("mmap(2) fail  path: %s fd: %d errno: %d", path, fd, errno);
        set_goto(-1, out_close);
    }

    buf.data = data;
    buf.size = st.st_size;

    LOG("Parsing %s", path);
    if (parse_macho(&buf) < 0) {
        set_goto(-1, out_unmap);
    }

out_unmap:
    (void) munmap(buf.data, buf.size);
out_close:
    (void) close(fd);
out_exit:
    return e;
}

int main(int argc, char *argv[])
{
    int i;

    if (argc < 2) {
        LOG_STDERR("Usage:\n\t%s file ...\n", basename(*argv));
        return 1;
    }

    for (i = 1; i < argc; i++) {
        parse_preflight(argv[i]);
        LOG("");
    }

    return 0;
}
