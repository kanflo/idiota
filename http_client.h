/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Andrea Greco (github.com/AndreaGreco)
 * Copyright (c) 2019 Johan Kanflo (github.com/kanflo)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __HTTP_CLIENT_H__
#define __HTTP_CLIENT_H__

/**
 * HTTP download callback used for buffer full and download finished
 * If size < 0 then an error occurred.
 * 
 */
typedef void (*http_get_cb)(char *data, int16_t size);

typedef enum  {
    HTTP_OK                        =  200,
    HTTP_NOT_FOUND                 =  404,
    HTTP_DNS_LOOKUP_FAILED         = 1000,
    HTTP_SOCKET_ALLOCATION_FAILED  = 1001,
    HTTP_SOCKET_CONNECTION_FAILED  = 1002,
    HTTP_REQUEST_SEND_FAILED       = 1003,
    HTTP_DOWNLOAD_SIZE_MISMATCH    = 1004,
    HTTP_PARAM_ERROR               = 1005,
} http_client_state_t;

typedef struct  {
    char         *server;
    char         *port;
    char         *path;
    char         *buffer;

    /** @todo: use values from sysparam */
    char         *node_id;
    char         *hw_rev;
    char         *node_type;

    uint16_t     buffer_size;
    http_get_cb  buffer_full_cb;
    http_get_cb  finished_cb;
} http_get_request_t;

http_client_state_t http_get(http_get_request_t *info);

#endif // __HTTP_CLIENT_H__
