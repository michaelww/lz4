/* */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crc32_pcl_intel.h"

#define CHUNKSIZ (8 << 20)
#define ERR(...) (fprintf(stderr, "Error: "  __VA_ARGS__), 0)
int main(int king, char *kong[])
{
    FILE *fin;
    unsigned char *buf;
    if (king < 2 || !strcmp(kong[1], "-"))
        fin = stdin;
    else if (!(fin = fopen(kong[1], "r")))
        return !ERR("'%s', %s\n", kong[1], strerror(errno));
    buf = malloc(CHUNKSIZ);
    if (!buf) return !ERR("%s\n", strerror(errno));

    uint32_t crc_sum = 1;

    while (1) {
        size_t read_len = fread(buf, 1, CHUNKSIZ, fin);
        if (!read_len)
            break;
        crc_sum = crc_pcl(buf, read_len, crc_sum);
    }
    fprintf(stdout, "crc32c of %s: %08x\n", kong[1], crc_sum);

    fclose(fin);
    free(buf);
}
