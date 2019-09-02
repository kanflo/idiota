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

#ifndef __IDIOTA_H__
#define __IDIOTA_H__

#include "http_client.h"

typedef enum {

    /** OTA is idle */
    OTA_IDLE                     = 0,
    /** OTA has started */
    OTA_START                    = 1,
    /** OTA is running */
    OTA_RUNNING                  = 2,
    /** OTA has successfully completed upgrade process */
    OTA_COMPLETED                = 3,
    /** Sha256 sum does not fit downloaded sha256 */
    OTA_SHA256_MISMATCH          = 4,
    /** rboot has only one slot configured */
    OTA_ONE_SLOT_ONLY            = 5,
    /** rboot failed switching between roms */
    OTA_FAIL_SET_NEW_SLOT        = 6,
    /** rboot verification failed */
    OTA_IMAGE_VERIFY_FAILED      = 7,

    // Keep the following aligned with \ref http_client_state_t

    /** DNS lookup has failed */
    OTA_DNS_LOOKUP_FAILED        = HTTP_DNS_LOOKUP_FAILED,
    /** Impossible allocate required socket */
    OTA_SOCKET_ALLOCATION_FAILED = HTTP_SOCKET_ALLOCATION_FAILED,
    /** Server unreachable, impossible connect */
    OTA_SOCKET_CONNECTION_FAILED = HTTP_SOCKET_CONNECTION_FAILED,
    /** Impossible send HTTP request */
    OTA_REQUEST_SEND_FAILED      = HTTP_REQUEST_SEND_FAILED,
    /** Downloaded size don't match with server declared size */
    OTA_DOWNLOAD_SIZE_MISMATCH   = HTTP_DOWNLOAD_SIZE_MISMATCH,
} ota_status_t;


typedef void (*ota_cb_t)(ota_status_t status);

/**
 * \brief Create ota info.
 * Struct that contains all info for start ota.
 */
typedef struct {
    /** Server ip or name */
    char *server;
    /** Server port */
    char *port;
    /** Interval in seconds to check for upgrades */
    uint32_t check_interval; 
    /** Callback for informing app about OTA progress and status */
    ota_cb_t ota_cb;

    /** The following fields are used to identify a suitable firmware for
     *  your node. You need to set at least one field, but which are
     *  completely up to you. */

    /** Node ID */
    char *node_id;
    /** Node type */
    char *node_type;
    /** Hardware revision */
    char *hw_rev;

} ota_info;

/**
 * @brief      Initialize OTA system. Must only be called once.
 *
 * @param      ota_settings  The OTA settings
 *
 * @return     true if init went well
 */
bool ota_init(ota_info *ota_settings);

/**
 * @brief      Request OTA to be run immediately
 */
void ota_run(void);

#endif // __IDIOTA_H__
