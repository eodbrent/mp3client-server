//requires dependencies "libao" & "libmpg123"
#include <stdio.h>
#include <ao/ao.h>
#include <mpg123.h>

#define BITS 8

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <audio_file>\n", argv[0]);
        return 1;
    }

    char *audio_file = argv[1];

    mpg123_handle *mh;
    unsigned char *buffer;
    size_t buffer_size;
    size_t done;
    int err;

    int driver;
    ao_device *dev;

    ao_sample_format format;
    int channels, encoding;
    long rate;

    /* Initializations */
    ao_initialize();
    driver = ao_default_driver_id();
    mpg123_init();
    mh = mpg123_new(NULL, &err);
    buffer_size = mpg123_outblock(mh);
    buffer = (unsigned char*) malloc(buffer_size * sizeof(unsigned char));

    /* Open the file and get the decoding format */
    mpg123_open(mh, audio_file);
    mpg123_getformat(mh, &rate, &channels, &encoding);

    /* Set the output format and open the output device */
    format.bits = mpg123_encsize(encoding) * BITS;
    format.rate = rate;
    format.channels = channels;
    format.byte_format = AO_FMT_NATIVE;
    format.matrix = 0;
    dev = ao_open_live(driver, &format, NULL);

    /* Decode and play */
    while (mpg123_read(mh, buffer, buffer_size, &done) == MPG123_OK)
        ao_play(dev, (char*)buffer, done); // Cast buffer to char*

    /* Clean up */
    free(buffer);
    ao_close(dev);
    mpg123_close(mh);
    mpg123_delete(mh);
    mpg123_exit();
    ao_shutdown();

    return 0;
}
