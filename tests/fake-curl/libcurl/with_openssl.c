#include "curl.h"


static const char *protocols[] = {
};

static curl_version_info_data version_info = {
    /* age */
    3,
    /* version */
    "",
    /* version_num */
    0,
    /* host */
    "",
    /* features */
    0,
    /* ssl_version */
    "OpenSSL/1.0.1a",
    /* ssl_version_num */
    0,
    /* libz_version */
    "",
    /* protocols */
    protocols
};

curl_version_info_data *curl_version_info(CURLversion type) {
    return &version_info;
}
