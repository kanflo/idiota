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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sysparam.h>
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "espressif/esp_common.h"
#include "http_client.h"

/** For testing */
//#define DEBUG

#define MODULE "HTTP"

#if defined(DEBUG)
# ifndef MODULE
#  error "Module not defined"
# endif
# define DEBUG_PRINT(fmt, args ...) \
    printf("[%s]\t" fmt "\n", MODULE, ## args)
#else
    # define DEBUG_PRINT(fmt, args ...)
#endif // DEBUG

#define delay_ms(ms) vTaskDelay((ms) / portTICK_PERIOD_MS)

typedef void (*handle_http_field)(char *);

struct http_header_table {
    char *field_name;
    handle_http_field http_field_cb;
};

/** Response struct */
struct http_response {
    uint32_t response_code;
    uint32_t length;
};

/** HTTP header template */
static const char *http_header_template =
  "GET %s HTTP/1.1\r\n"
  "Host: %s\r\n"
  "User-Agent: esp-open-rtos/0.1 esp8266\r\n"
  "Connection: close\r\n"
  "node_type: %s\r\n"
  "node_id: %s\r\n"
  "hw_rev: %s\r\n"
  "\r\n";
//  @todo: "MAC: %s\r\n"

#define MAX_REQUEST_SIZE (256)
static char request[MAX_REQUEST_SIZE];

static const struct addrinfo hints = {
    .ai_family   = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM,
};

static struct http_response http_reponse;

/** HTTP header field, add handler and register in HTTP table callback */
static void parse_content_length(char *field_name)
{
    field_name += 16; // strlen("Content-Length:"), skip useless part
    while (*field_name) {
        if (isdigit((int) *field_name)) {
            http_reponse.length = (uint32_t) strtol(field_name, &field_name, 10);
        }
        else {
            field_name++;
        }
    }
}

static inline void parse_http_status(char *field_name)
{
    field_name += 8; // Skip HTTP/1.0

    while (*field_name) {
        if (isdigit((int) *field_name)) {
            http_reponse.response_code = (uint32_t) strtol(field_name, &field_name, 10);
        } else {
            field_name++;
        }
    }
}

// HTTP field name handling callback
struct http_header_table http_header[] = {
    { .field_name = "Content-Length", .http_field_cb = parse_content_length },
};

static inline void parse_http_header(char *header)
{
    char *str1, *str2, *field_name, *subfield_name, *saveptr1, *saveptr2;
    const char line_split[] = "\r\n", delimiter[] = ":";
    uint32_t j, i;

    for (j = 1, str1 = header;; j++, str1 = NULL) {
        field_name = strtok_r(str1, line_split, &saveptr1);
        if (field_name == NULL) {
            break;
        }

        str2 = field_name;
        subfield_name = strtok_r(str2, delimiter, &saveptr2);
        if (subfield_name == NULL) {
            break;
        }

        /** @todo: clean this up */
        if (j == 1) {
            /* HTTP header, response, HTTP version and status */
            parse_http_status(field_name);
            continue;
        }

        for (i = 0; i < sizeof(http_header) / sizeof(struct http_header_table); i++) {
            if (!strcmp(subfield_name, http_header[i].field_name)) {
                if (http_header[i].http_field_cb) {
                    http_header[i].http_field_cb(field_name);
                }
            }
        }
    }
}

http_client_state_t http_get(http_get_request_t *req)
{
    struct addrinfo *res;
    uint32_t body_size, full;
    int32_t read_byte;
    int err, sock;
    char *buf_ptr;

    if (!req || !req->buffer_full_cb || !req->finished_cb) {
        return HTTP_PARAM_ERROR;
    }

    /** Make sure we don't find an old HTTP header ending in this buffer */
    bzero((void*) req->buffer, req->buffer_size);
    err = getaddrinfo(req->server, req->port, &hints, &res);

    if (err != 0 || res == NULL) {
        if (res) {
            freeaddrinfo(res);
        }
        return HTTP_DNS_LOOKUP_FAILED;
    }

    sock = socket(res->ai_family, res->ai_socktype, 0);
    if (sock < 0) {
        freeaddrinfo(res);
        return HTTP_SOCKET_ALLOCATION_FAILED;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        close(sock);
        freeaddrinfo(res);
        return HTTP_SOCKET_CONNECTION_FAILED;
    }

    freeaddrinfo(res);

    /** Setup http request */
#if 0
    /** @todo: include MAC address in request */
    char mac[13];
    if (!sdk_wifi_get_macaddr(STATION_IF, (uint8_t*) mac)) {
        mac[0] = 0;
    }
#endif

#if 0
    /** @todo: read parameters from sysparam instead of the app providing via
      * the init call. */
    char *node_type = 0;
    char *node_id = 0;
    char *hw_rev = 0;

    if (SYSPARAM_OK != sysparam_get_string("sys.nodetype", &node_type)) {
    }
    if (SYSPARAM_OK != sysparam_get_string("sys.nodeid", &node_id)) {
    }
    if (SYSPARAM_OK != sysparam_get_string("sys.hwrev", &hw_rev)) {
    }
#endif

    if (sizeof(request) == snprintf((char *) request, sizeof(request), http_header_template,
        req->path, req->server, req->node_type ? req->node_type : "NA",
        req->node_id ? req->node_id : "NA",
        req->hw_rev ? req->hw_rev : "NA")) {
        printf("Error: HTTP request buffer is too small\n");
    }
    DEBUG_PRINT("Request length %d", strlen(request));
    DEBUG_PRINT("--------------------");
    DEBUG_PRINT("%s", request);
    DEBUG_PRINT("--------------------");
    if (write(sock, (char*) request, strlen((char*) request)) < 0) {
        close(sock);
        return HTTP_REQUEST_SEND_FAILED;
    }

    body_size = 0;
    buf_ptr = req->buffer;
    full = 0;

    do {
        /** Ping watchdog */
        delay_ms(50);
        uint32_t free_buff_space = req->buffer_size - full;

        read_byte = read(sock, buf_ptr, free_buff_space);
        DEBUG_PRINT("Recv %d", read_byte);
        if (read_byte < 0) {
            printf("Error: caught error while reading\n");
            close(sock);
            return 404; /** or whatever */
        } else if (read_byte == 0) {
            continue;
        }

        buf_ptr += read_byte;
        full += read_byte;

        if (body_size == 0) {
            // Is first chunk, then it contains HTTP header, parse it.
            int32_t chunk_size;
            char *body_start;

            body_start = strstr(req->buffer, "\r\n\r\n");

            if (body_start != NULL) {
                /** Null terminate header */
                *body_start = 0;
                DEBUG_PRINT("Header length %d", body_start - req->buffer);
                DEBUG_PRINT("--------------------");
                DEBUG_PRINT("%s", req->buffer);
                DEBUG_PRINT("--------------------\n");
                /** Move to start of body */
                body_start += 4;
            } else {
                /** Continue reading if complete HTTP header has not been read */
                continue;
            }

            parse_http_header(req->buffer);
            chunk_size = buf_ptr - body_start;

            memmove(req->buffer, body_start, chunk_size);
            buf_ptr = req->buffer + chunk_size;

            full = chunk_size;
            body_size = chunk_size;

            if (http_reponse.response_code != HTTP_OK) {
                full = -1;
                break;
            }
            continue;
        }
        body_size += read_byte;

        if (full == req->buffer_size) {
            req->buffer_full_cb(req->buffer, full);
            bzero(req->buffer, req->buffer_size);
            buf_ptr = req->buffer;
            full = 0;
        }
    } while (read_byte > 0);

    req->finished_cb(req->buffer, full);
    if (body_size != http_reponse.length) {
        http_reponse.response_code = HTTP_DOWNLOAD_SIZE_MISMATCH;
    }

#if 0
    if (node_type) {
        free(node_type);
    }
    if (node_id) {
        free(node_id);
    }
    if (hw_rev) {
        free(hw_rev);
    }
#endif

    close(sock);
    return http_reponse.response_code;
}
