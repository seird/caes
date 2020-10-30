#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "aes.h"


#if (!defined(TEST) && !defined(SHARED) && !defined(BENCHMARK))


static void
print_usage(char * s)
{
    printf("Usage: %s -[e|d] [-m mode] [-s size] -i file_in -o file_out PASSPHRASE\n"
           "\n"
           "-e                encrypt\n"
           "-d                decrypt\n"
           "-i <file_in>      path to file to encrypt\n"
           "-o <file_out>     path to encrypted output file\n"
           "-m <mode>         AES mode: ctr, cbc, ofb, cfb or ecb; default ctr\n"
           "-s <size>         AES key size: 128, 192 or 256; default 256\n",
           s);
}


static char *
__strlwr(char * s)
{
    char * l = strdup(s);
    char * _l = l;
    while (*_l) {
        if (*_l >= 'A' && *_l <= 'Z') {
            *_l += 'a'-'A';
        }
        _l++;
    }
    return l;
}


int
main(int argc, char * argv[])
{
    // Default parameters
    bool encrypting = true;
    enum KeySize key_size = AES_256;
    enum Mode mode = AES_CTR;
    char * fin = NULL;
    char * fout = NULL;

    char * mode_temp = NULL;
    int size_temp;
    int opt;
    while ((opt = getopt(argc, argv, "edi:m:o:s:")) != -1) {
        switch (opt) {
        case 'e':
            encrypting = true;
            break;
        case 'd':
            encrypting = false;
            break;
        case 'i':
            fin = strdup(optarg);
            break;
        case 'o':
            fout = strdup(optarg);
            break;
        case 's':
            size_temp = atoi(optarg);
            switch (size_temp) {
            case 128:
            case 192:
            case 256:
                key_size = size_temp;
                break;
            default:
                break;
            }
            break;
        case 'm':
            mode_temp = __strlwr(optarg);
            if (strcmp(mode_temp, "ctr") == 0) {
                mode = AES_CTR;
            } else if (strcmp(mode_temp, "cbc") == 0) {
                mode = AES_CBC;
            } else if (strcmp(mode_temp, "ofb") == 0) {
                mode = AES_OFB;
            } else if (strcmp(mode_temp, "cfb") == 0) {
                mode = AES_CFB;
            } else if (strcmp(mode_temp, "ecb") == 0) {
                mode = AES_ECB;
            }
            free(mode_temp);
            break;
        case '?':
            print_usage(argv[0]);
            return EXIT_FAILURE;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if ((fin == NULL) || (fout == NULL)) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (encrypting) {
        aes_encrypt_file(fin, fout, argv[optind], mode, key_size);
    } else {
        aes_decrypt_file(fin, fout, argv[optind], mode, key_size);
    }

    free(fin);
    free(fout);

    return EXIT_SUCCESS;    
}
#endif
