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
#include <ctype.h>
#include "arch/cc.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include <sysparam.h>
#include <espressif/spi_flash.h>
#include <espressif/esp_system.h>
#include <espressif/esp_common.h>
#include "mbedtls/sha256.h"
#include "idiota.h"
#include "rboot-api.h"
#include "rboot.h"

/** For testing */
//#define DEBUG

#define MODULE "OTA"

#if defined(DEBUG)
 #ifndef MODULE
  #error "MODULE not defined"
 #endif
 #define DEBUG_PRINT(fmt, args ...) \
    printf("[%s]\t" fmt "\n", MODULE, ## args)
#else
    # define DEBUG_PRINT(fmt, args ...)
#endif // DEBUG

#define OTA_PRINT(fmt, args ...) \
    printf("[%s]\t" fmt "\n", MODULE, ## args)

/** 1MB images max at the moment */
#define MAX_IMAGE_SIZE        1024*1024
#define READ_BUFFER_LEN       512
#define SHA256_SIZE_BIN       32
#define SHA256_SIZE_HEX       2 * SHA256_SIZE_BIN
#define SHA256_CONV_STEP_SIZE 4

#if SECTOR_SIZE % READ_BUFFER_LEN != 0
 #error "SECTOR_SIZE %% READ_BUFFER_LEN > 0"
#endif

#define SECTOR_BUFFER_SIZE (SECTOR_SIZE)
#define delay_ms(ms) vTaskDelay((ms) / portTICK_PERIOD_MS)

static ota_info *ota_settings;
static mbedtls_sha256_context *sha256_ctx;
static uint32_t flash_offset;
static uint32_t max_image_size;
static unsigned char *sha256_image;
static uint16_t *sha256_bin;
static char *sha256_hex;
static char *sha256_wrt_ptr;
static http_get_request_t get_req;
static uint32_t firmware_size = 0;

static volatile uint32_t ota_countdown;

static void ota_task(void *params);

/**
 * @brief      allback from HTTP buffered client, for OTA firmware
 *
 * @param      data  Downloaded data
 * @param[in]  size  Downloaded size or -1 if download failed
 */
static void firmware_download_callback(char *data, int16_t size)
{
    if (size < 0) {
        return;
    }
    firmware_size += size;
    OTA_PRINT("Downloaded %d bytes", firmware_size);
    /** Inform app OTA is progressing */
    ota_settings->ota_cb(OTA_RUNNING);

    mbedtls_sha256_update(sha256_ctx, (const unsigned char *) data, size);

    if (flash_offset + size > max_image_size) {
        OTA_PRINT("Error: flash overflow");
        /** @todo: this isn't handled by http_client.c anyhow... */
        //return -1;
    }

    if (flash_offset % SECTOR_SIZE == 0) {
        uint32_t sector;
        sector = flash_offset / SECTOR_SIZE;
        sdk_spi_flash_erase_sector(sector);
    }

    sdk_spi_flash_write(flash_offset, (uint32_t *) data, size);
    flash_offset += size;
}

/**
 * @brief      SHA256 HTTP download callback
 *
 * @param      data  Downloaded data
 * @param[in]  size  Downloaded size or -1 if download failed
 */
static void sha256_download_callback(char *data, int16_t size)
{
    if (size < 0) {
        return;
    }
    DEBUG_PRINT("Downloaded %d bytes of SHA256", size);
#if 0
    uint32_t i;
    for (i = 0; i < size; i++) {
        printf("%c", data[i]);
    }
    printf("\n");
#endif
    int curr_sha_size;
    /** Check that str does not contains other string with SHA256 */
    if (size > SHA256_SIZE_HEX) {
        size = SHA256_SIZE_HEX;
    }
    curr_sha_size = sha256_wrt_ptr - (char *) sha256_hex;
//    if (!(curr_sha_size > SHA256_SIZE_HEX)) {
    if (curr_sha_size <= SHA256_SIZE_HEX) {
        memcpy(sha256_wrt_ptr, data, size);
        sha256_wrt_ptr += size;
    }
}

/**
 * @brief      Convert a SHA256 hex string to binary
 *
 * @param      str  The string 'aabbcc...'
 * @param      bin  The bin 0xaabbcc..
 */
static void sha256_hex2bin(char *hex, uint16_t *bin)
{
    char tmp[SHA256_CONV_STEP_SIZE + 1];
    char *wrt_ptr;
    int i;

    wrt_ptr = hex;
    for (i = 0; i < SHA256_SIZE_HEX / SHA256_CONV_STEP_SIZE; i++) {
        uint16_t val;
        bzero(tmp, sizeof(tmp));
        memcpy(tmp, wrt_ptr, SHA256_CONV_STEP_SIZE);
        val = strtol(tmp, NULL, 16);
        bin[i] = LWIP_PLATFORM_HTONS(val);
        wrt_ptr += SHA256_CONV_STEP_SIZE;
    }
}

/**
 * @brief      Run OTA update
 *
 * @return     OTA_COMPLETED if all went well
 */
static ota_status_t ota_update(ota_info *settings)
{
    rboot_config rboot_config;
    http_client_state_t err;
    int slot;
    char *cur_sha256 = 0;
    firmware_size = 0;

    do {
        sha256_wrt_ptr = sha256_hex;
        sha256_hex[SHA256_SIZE_HEX] = '\0';
        mbedtls_sha256_init(sha256_ctx);

        OTA_PRINT("OTA checking");

        rboot_config = rboot_get_config();
        slot = (rboot_config.current_rom + 1) % rboot_config.count;

        if (slot == rboot_config.current_rom) {
            printf("Error: only one OTA slot is configured\n");
            err = OTA_ONE_SLOT_ONLY;
            break;
        }

        /** Validate the OTA slot parameter */
        if (rboot_config.current_rom == slot || rboot_config.count <= slot) {
            OTA_PRINT("Error: current rom set to unknown value:%d", rboot_config.current_rom);
        }

        /** Calculate flash limits */
        flash_offset = rboot_config.roms[slot];
        max_image_size = flash_offset + MAX_IMAGE_SIZE;

        /** Download latest sha256 */
        char temp[100];
        get_req.path           = "/firmware/";
        get_req.node_id = settings->node_id;
        get_req.hw_rev = settings->hw_rev;
        get_req.node_type = settings->node_type;
        get_req.finished_cb    = sha256_download_callback;
        get_req.buffer_full_cb = sha256_download_callback;

        bzero(sha256_bin, SHA256_SIZE_BIN);
        bzero(sha256_hex, SHA256_SIZE_HEX);
        DEBUG_PRINT("Downloading sha256...");
        err = http_get(&get_req);
        DEBUG_PRINT("  Status %d", err);

        if (err != HTTP_OK) {
            printf("Error: SHA256 download failed with %d\n", err);
            break;
        }

        DEBUG_PRINT("Downloaded SHA256 is %s", sha256_hex);
        if (SYSPARAM_OK == sysparam_get_string("sys.sha256", &cur_sha256)) {
            DEBUG_PRINT("Current SHA256 is    %s", cur_sha256);
            if (strcmp(cur_sha256, sha256_hex) == 0) {
                DEBUG_PRINT("No need to OTA");
                err = OTA_IDLE;
                break;
            }
        } else {
            DEBUG_PRINT("No current SHA256");
        }
        sha256_hex2bin(sha256_hex, sha256_bin);

        /** Inform app we're starting OTA */
        ota_settings->ota_cb(OTA_START);

        /** Download firmware */
        snprintf((char*) temp, sizeof(temp), "/firmware/%s", sha256_hex);
        get_req.path           = (char*) temp;
        get_req.finished_cb    = firmware_download_callback;
        get_req.buffer_full_cb = firmware_download_callback;
        mbedtls_sha256_starts(sha256_ctx, 0);
        DEBUG_PRINT("Downloading firmware image...");
        err = http_get(&get_req);
        DEBUG_PRINT("  Status %d", err);
        if (err != HTTP_OK) {
            break;
        }

        mbedtls_sha256_finish(sha256_ctx, sha256_image);
        mbedtls_sha256_free(sha256_ctx);

        if (0 != memcmp((void *) sha256_image, (void *) sha256_bin, SHA256_SIZE_BIN)) {
            OTA_PRINT("Downloaded SHA256 does not match downloaded binary");
            err = OTA_SHA256_MISMATCH;
            break;
        }

        /** Ping watchdog */
        delay_ms(100);

        uint32_t image_length;
        const char *err_msg;
        OTA_PRINT("Image will be saved in OTA slot %d", slot);
        if (rboot_verify_image(rboot_config.roms[slot], &image_length, &err_msg)) {
            vPortEnterCritical();
            if (!rboot_set_current_rom(slot)) {
                vPortExitCritical();
                err = OTA_FAIL_SET_NEW_SLOT;
                break;
            }
            vPortExitCritical();
            err = OTA_COMPLETED;
            sysparam_status_t status = sysparam_set_string("sys.sha256", sha256_hex);
            if (SYSPARAM_OK != status) {
                OTA_PRINT("Error: failed to store current sha256 in sysparam: %d", status);
            }
            break;
        } else {
            OTA_PRINT("rboot verification failed: %s", err_msg);
            err = OTA_IMAGE_VERIFY_FAILED;
            break;
        }
    } while(0);

    if (cur_sha256) {
        free(cur_sha256);
    }
    return err;
}

/**
 * @brief      The OTA task
 *
 * @param      params  ota_info settings
 */
static void ota_task(void *params)
{
    ota_info *settings = (ota_info*) params;
    OTA_PRINT("OTA task running");
    if (sdk_wifi_station_get_connect_status() != STATION_GOT_IP) {
        OTA_PRINT("OTA waiting for IP...");
        /** Wait until we have joined AP and are assigned an IP */
        while (sdk_wifi_station_get_connect_status() != STATION_GOT_IP) {
            delay_ms(1000);
        }
        OTA_PRINT("  done");
    }

    ota_countdown = settings->check_interval;
    while (1) {
        ota_countdown--;
        if (ota_countdown == 0) {
            ota_status_t status;
            status = ota_update(settings);
            if (status != 0) {
                OTA_PRINT("  OTA status %d", status);
            }

            if (status != OTA_IDLE) {
                settings->ota_cb(status);
            }
            ota_countdown = settings->check_interval;
            if(status == OTA_COMPLETED) {
                OTA_PRINT("Rebooting");
                sdk_system_restart(); 
            } else {
                delay_ms(1000);
            }
        }
    }
}

/**
 * @brief      Initialize OTA system. Must only be called once.
 *
 * @param      ota_settings  The OTA settings
 *
 * @return     true if init went well
 */
bool ota_init(ota_info *_ota_settings)
{
    if (ota_settings) {
        OTA_PRINT("ERROR: OTA init called twice");
        return false;
    }
    OTA_PRINT("OTA init");

    /** Node ID */
    if (!(_ota_settings->node_id || _ota_settings->node_type || _ota_settings->hw_rev)) {
        OTA_PRINT("ERROR: Nothing to identify a firmware for this node");
        return false;
    }

    get_req.buffer = malloc(SECTOR_BUFFER_SIZE);
    if (!get_req.buffer) {
        printf("Error: malloc failed in %s : %d", __FILE__, __LINE__);
    }
    get_req.buffer_size = SECTOR_BUFFER_SIZE;

    /** Check memory alignment, must be aligned */
    if ((uint32_t) get_req.buffer % sizeof(uint32_t)) {
        OTA_PRINT("Error: malloc returned unaligned memory");
        free(get_req.buffer);
        return false;
    }

    sha256_ctx   = malloc(sizeof(mbedtls_sha256_context));
    sha256_image = malloc(SHA256_SIZE_BIN);
    sha256_bin   = malloc(SHA256_SIZE_BIN);
    sha256_hex   = malloc(SHA256_SIZE_HEX + 1);

    if (!sha256_ctx) {
        printf("Error: failed to allocate sha256_ctx\n");
        return false;
    }
    if (!sha256_image) {
        printf("Error: failed to allocate sha256_image\n");
        return false;
    }
    if (!sha256_bin) {
        printf("Error: failed to allocate sha256_bin\n");
        return false;
    }
    if (!sha256_hex) {
        printf("Error: failed to allocate sha256_hex\n");
        return false;
    }

    if (_ota_settings->server && _ota_settings->port) {
        /** @todo: copy settings as ota_settings may be out of scope when we need them */
        ota_settings = _ota_settings;
        get_req.server = ota_settings->server;
        get_req.port = ota_settings->port;
        xTaskCreate(ota_task, "ota_task", 2*4096, ota_settings, 2, NULL);
        DEBUG_PRINT("Buffer size: %d", SECTOR_SIZE);
        char *cur_sha256 = 0;
        if (SYSPARAM_OK == sysparam_get_string("sys.sha256", &cur_sha256)) {
            OTA_PRINT("Current SHA256 is %s", cur_sha256);
            free(cur_sha256);
        }
        return true;

    } else {
        OTA_PRINT("Missing OTA settings");
        return false;
    }
}

/**
 * @brief      Request OTA to be run immediately
 */
void ota_run(void)
{
    /** Make OTA start on next wakeup */
    ota_countdown = 1;
}
