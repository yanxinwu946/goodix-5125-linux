/*
 * Goodix TLS driver for libfprint -- chip 27c6:5125 (Milan/ST411SEC family).
 *
 * Copyright (C) 2026 libfprint contributors
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

// Architecture:
//   * Transport reused verbatim from the goodixtls base (goodix.c / goodixtls.c):
//     activation, TLS-PSK handshake (OpenSSL) with the per-device session key,
//     MCU_GET_IMAGE.
//   * FpImageDevice scan layer IS used (like 511, NOT 5F10's sigfm approach):
//     64x80 sensor with 88 scan width, crop_frame decodes and crops.
//   * 5125-specific empirical facts:
//     - ENABLE_CHIP body is "01 02" (the generic helper emits "01 00").
//     - RESET reply number is 2048 (same as 511; 5F10 is 1024).
//     - Firmware string is "GF_ST411SEC_APP_12509".
//     - Preset-PSK flags are 0xbb020003 (same family).
//     - MCU config payload is 256 bytes (captured from chip).
//     - FDT mode payload is 14 bytes (same as 511).
//     - Sensor streams 88 scanlines x 64 px, presented STRAIGHT (no transpose)
//       with ridges inverted dark (same crop_frame as 511).
//   * Per-device secrets (TLS-PSK session key) loaded from disk at activation,
//     like 5F10. They are device-specific and NOT compiled in.

#include "fp-device.h"
#include "fpi-device.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"
#include "fp-image-device.h"
#include "fpi-image-device.h"
#include "fpi-image.h"
#include "fpi-assembling.h"
#include "fp-image.h"
#include "gusb/gusb-device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <openssl/ssl.h> // goodixtls.h references SSL/SSL_CTX types

#include "drivers_api.h"
#include "goodix.h"
#include "goodix_proto.h"
#include "goodixtls.h"
#include "goodix5xx.h"
#include "goodix5125.h"

#define FP_COMPONENT "goodixtls5125"

#define GOODIX5125_WIDTH 64
#define GOODIX5125_HEIGHT 80
#define GOODIX5125_SCAN_WIDTH 64
#define GOODIX5125_FRAME_SIZE (GOODIX5125_WIDTH * GOODIX5125_HEIGHT)
// The leftmost 9 columns are a dead dark band (sensor boundary) and the
// rightmost 2 columns carry edge artifacts. NBIS LFS turns those straight
// edges into ~10-20 collinear false minutiae that bozorth can never use,
// while only 1-3 real ridge minutiae survive in the center on flat frames -
// that is why the 20-print template self-matched 0/190. Cropping them out
// leaves only real minutiae: a good frame keeps ~19, a flat low-contrast
// frame drops to 0 and the framework then returns "Minutiae detection
// failed, please retry" so the user is forced to press properly.
#define GOODIX5125_CROP_LEFT 9
#define GOODIX5125_CROP_RIGHT 2
#define GOODIX5125_CROP_WIDTH \
  (GOODIX5125_WIDTH - GOODIX5125_CROP_LEFT - GOODIX5125_CROP_RIGHT)
// For every 4 pixels there are 6 bytes and there are 8 extra start bytes and 5
// extra end
#define GOODIX5125_RAW_FRAME_SIZE \
  8 + (GOODIX5125_HEIGHT * GOODIX5125_SCAN_WIDTH) / 4 * 6 + 5

typedef unsigned short Goodix5125Pix;

struct _FpiDeviceGoodixTls5125
{
  FpiDeviceGoodixTls5xx parent;

  guint8 *tls_psk;  // 32 bytes loaded from disk

  // OTP dump captured at activation (reply of GOODIX_CMD_READ_OTP, 64 bytes).
  // Bytes 46..49 hold the per-device DAC calibration the Windows driver
  // re-applies at init; the 256-byte config blob bakes in *another* device's
  // DAC values, so we must re-write our own from OTP before each scan.
  guint8 otp[64];
  guint16 otp_len;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixTls5125, fpi_device_goodixtls5125, FPI,
                      DEVICE_GOODIXTLS5125, FpiDeviceGoodixTls5xx);
G_DEFINE_TYPE (FpiDeviceGoodixTls5125, fpi_device_goodixtls5125,
               FPI_TYPE_DEVICE_GOODIXTLS5XX);

// ---- activation SSM (run once at open) --------------------------------------------

enum activate_states {
  ACTIVATE_READ_AND_NOP,
  ACTIVATE_TLS_PRE,  // 0xd4 before enable_chip — 5125 needs this
  ACTIVATE_ENABLE_CHIP,
  ACTIVATE_NOP,
  ACTIVATE_CHECK_FW_VER,
  ACTIVATE_CHECK_PSK,
  ACTIVATE_RESET,
  ACTIVATE_SET_MCU_IDLE,
  ACTIVATE_READ_OTP,
  ACTIVATE_UPLOAD_MCU_CONFIG,
  ACTIVATE_SET_POWERDOWN_SCAN_FREQUENCY,
  ACTIVATE_NUM_STATES,
};

// 5125 wants ENABLE_CHIP body "01 02"; the generic helper emits "01 00".
static void
send_enable_chip (FpDevice *dev, GoodixNoneCallback callback, gpointer user_data)
{
  guint8 payload[] = {0x01, 0x02};
  GoodixCallbackInfo *cb_info = malloc (sizeof (GoodixCallbackInfo));

  cb_info->callback = G_CALLBACK (callback);
  cb_info->user_data = user_data;
  goodix_send_protocol (dev, GOODIX_CMD_ENABLE_CHIP, payload, sizeof (payload),
                        NULL, TRUE, GOODIX_TIMEOUT, FALSE, goodix_receive_none, cb_info);
}

// Forward declaration for check_preset_psk (defined after activate_run_state)
static void check_preset_psk (FpDevice *dev, gboolean success, guint32 flags, guint8 *psk,
                              guint16 length, gpointer ssm, GError *error);

// Capture the 64-byte OTP dump instead of discarding it: bytes 46..49 are the
// per-device DAC calibration (verified against WBDI: otp[46]=0xb7 -> dac 0xb78,
// otp[47]=0xb9, otp[48]=0xb7, otp[49]=0xb7).
static void
on_read_otp (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls5125 *self = FPI_DEVICE_GOODIXTLS5125 (dev);

  if (err) { fpi_ssm_mark_failed (ssm, err); return; }
  self->otp_len = MIN (len, sizeof (self->otp));
  memcpy (self->otp, data, self->otp_len);
  fp_dbg ("captured %u-byte OTP dump", self->otp_len);
  fpi_ssm_next_state (ssm);
}

// Python reference (exp5125_v2.py upload_config_raw): the 256-byte config blob
// is already a complete message (a0 pack header + 0x90 protocol frame + payload
// + checksum, zero-padded to 256). Send it raw over bulk OUT; the device then
// ACKs (protocol cmd 0xb0, ACK payload echoes expected_cmd=0x90) and replies
// with a protocol message cmd=0x90 whose payload[0]==0x01 means success.
static void
on_config_reply (FpDevice *dev, guint8 *data, guint16 length,
                 gpointer user_data, GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixSuccessCallback callback = (GoodixSuccessCallback) cb_info->callback;

  if (error)
    {
      callback (dev, FALSE, cb_info->user_data, error);
      return;
    }

  if (length < 1)
    {
      g_set_error (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid config upload reply length: %d", length);
      callback (dev, FALSE, cb_info->user_data, error);
      return;
    }

  callback (dev, data[0] == 0x01, cb_info->user_data, NULL);
}

static void
send_raw_config (FpDevice *dev, GoodixSuccessCallback callback, gpointer user_data)
{
  GoodixCallbackInfo *cb_info = malloc (sizeof (GoodixCallbackInfo));

  cb_info->callback = G_CALLBACK (callback);
  cb_info->user_data = user_data;

  // Send the self-contained 256-byte blob raw; the device echoes
  // GOODIX_CMD_UPLOAD_CONFIG_MCU (0x90) in both ACK and reply.
  goodix_send_raw_command (dev, GOODIX_CMD_UPLOAD_CONFIG_MCU,
                           goodix_5125_config, sizeof (goodix_5125_config),
                           NULL, GOODIX_TIMEOUT, TRUE, on_config_reply, cb_info);
}

static void
activate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_READ_AND_NOP:
      goodix_start_read_loop (dev);
      goodix_send_nop (dev, goodixtls5xx_check_none, ssm);
      break;

    case ACTIVATE_TLS_PRE:
      fp_dbg ("sending 0xd4 (TLS_SUCCESSFULLY_ESTABLISHED) before enable_chip");
      goodix_send_tls_successfully_established (dev, goodixtls5xx_check_none, ssm);
      break;

    case ACTIVATE_ENABLE_CHIP:
      send_enable_chip (dev, goodixtls5xx_check_none, ssm);
      break;

    case ACTIVATE_NOP:
      goodix_send_nop (dev, goodixtls5xx_check_none, ssm);
      break;

    case ACTIVATE_CHECK_FW_VER:
      goodix_send_query_firmware_version (dev, goodixtls5xx_check_firmware_version, ssm);
      break;

    case ACTIVATE_CHECK_PSK:
      goodix_send_preset_psk_read (dev, GOODIX_5125_PSK_FLAGS, 0, check_preset_psk, ssm);
      break;

    case ACTIVATE_RESET:
      goodix_send_reset (dev, TRUE, 20, goodixtls5xx_check_reset, ssm);
      break;

    case ACTIVATE_SET_MCU_IDLE:
      goodix_send_mcu_switch_to_idle_mode (dev, 20, goodixtls5xx_check_idle, ssm);
      break;

    case ACTIVATE_READ_OTP:
      goodix_send_read_otp (dev, on_read_otp, ssm);
      break;

    case ACTIVATE_UPLOAD_MCU_CONFIG:
      send_raw_config (dev, goodixtls5xx_check_config_upload, ssm);
      break;

    case ACTIVATE_SET_POWERDOWN_SCAN_FREQUENCY:
      goodix_send_set_powerdown_scan_frequency (dev, 100, goodixtls5xx_check_powerdown_scan_freq, ssm);
      break;
    }
}

static void
open_tls_complete (FpDevice *dev, gpointer user_data, GError *error)
{
  // The TLS-PSK handshake itself already succeeded (verified in tls_handshake_done
  // via goodix_tls_server_accept_ok). The only error that can arrive here is a
  // timeout on the follow-up 0xd4 (TLS_SUCCESSFULLY_ESTABLISHED) confirmation:
  // once the TLS channel is up the 5125 chip stops ACKing plain message-protocol
  // commands (observed on 27c6:5125 — only TLS records get replies). Treat that
  // as best-effort, not fatal, or open() always fails right after a good handshake.
  if (error)
    fp_warn ("TLS open: %s (ignored, handshake succeeded)", error->message);
  fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), NULL);
}

static void
activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    {
      fp_err ("failed during activation: %s", error->message);
      fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  // Bring up the real TLS-PSK channel; open completes when the handshake finishes.
  goodix_tls_init (dev, open_tls_complete, NULL);
}

// Check the format of the sensor's pairing validator. The TLS handshake
// uses the PSK loaded from disk.
static void
check_preset_psk (FpDevice *dev, gboolean success, guint32 flags, guint8 *psk,
                  guint16 length, gpointer ssm, GError *error)
{
  g_autofree gchar *psk_str = NULL;

  if (error) { fpi_ssm_mark_failed (ssm, error); return; }
  if (!success)
    {
      fpi_ssm_mark_failed (ssm, g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED,
                                             "Failed to read PSK from device"));
      return;
    }

  psk_str = data_to_str (psk, length);
  fp_dbg ("Device PMK hash: 0x%s (flags 0x%08x)", psk_str, flags);
  if (flags != GOODIX_5125_PSK_FLAGS || length != GOODIX_5125_PSK_LEN)
    {
      fpi_ssm_mark_failed (ssm, g_error_new (G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                                             "Unexpected PSK reply: flags=0x%08x len=%u",
                                             flags, length));
      return;
    }
  fpi_ssm_next_state (ssm);
}

// ---- scan SSM (FpImageDevice flow) --------------------------------------------------
//
// The 5125 does NOT use the 5xx two-stage FDT calibration dance. Instead it
// needs the sequence captured from the Windows driver (WBDI.log) and mirrored
// by the realpsk reference script:
//   QUERY_MCU -> FDT1 -> NAV -> FDT2 -> READ_REG -> WRITE_DAC -> GET_IMG
// NAV (0x50) and READ_REG (0x82) were the missing steps vs. the old
// FDT1->FDT2->PREBULK->GET_IMG attempt (which the third-party avail5125 repo
// reproduced and also failed with). The DAC registers (0x0220/0x0236/0x0238/
// 0x023a) are written from OUR device's OTP (bytes 46..49), because the 256-byte
// config blob bakes in another device's DAC values.
// The chip only returns an image while a finger is pressed, so GET_IMG uses a
// long timeout instead of GOODIX_TIMEOUT.

enum scan5125_states {
  SCAN5125_QUERY_MCU,
  SCAN5125_FDT_SWITCH_1,
  SCAN5125_NAV,
  SCAN5125_FDT_SWITCH_2,
  SCAN5125_READ_REG,
  SCAN5125_WRITE_DAC,
  SCAN5125_GET_IMG,
  SCAN5125_DONE,
  SCAN5125_NUM_STATES,
};

// GET_IMG waits for the user to press the finger; the chip sends nothing until
// it does. 30 s matches the fprintd enroll capture window.
#define GOODIX5125_GET_IMG_TIMEOUT_MS (30000)

typedef struct
{
  guint8 reply1[32];
  guint16 reply1_len;
  guint8 dac_writes_done;  // 0..4, index of the next DAC register to write
} Scan5125Data;

static FpImage *
crop_frame (guint8 *frame)
{
  FpImage *img = fp_image_new (GOODIX5125_CROP_WIDTH, GOODIX5125_HEIGHT);

  img->flags |= FPI_IMAGE_PARTIAL;
  for (int y = 0; y != GOODIX5125_HEIGHT; ++y)
    {
      for (int x = 0; x != GOODIX5125_CROP_WIDTH; ++x)
        {
          const int idx = (x + GOODIX5125_CROP_LEFT) + y * GOODIX5125_SCAN_WIDTH;
          img->data[x + y * GOODIX5125_CROP_WIDTH] = frame[idx];
        }
    }
  return img;
}

// Nearest-neighbour integer upscale. The 64x80 sensor has a ridge period of
// ~6px; bilinear resampling (fpi_image_resize) smears those ridges flat and
// NBIS then extracts ~0 minutiae at any scale. Block replication preserves the
// ridge edges, and empirically GOODIX5125_UPSCALE_FACTOR=6 lands the ~6px
// period on NBIS LFS's ideal ~36px ridge spacing (16+ minutiae per frame,
// bozorth self-match >= 24). Verified offline on live dumps.
#define GOODIX5125_UPSCALE_FACTOR (6)

static FpImage *
goodix5125_upscale_nn (FpImage *img)
{
  const guint factor = GOODIX5125_UPSCALE_FACTOR;
  const guint nw = img->width * factor;
  const guint nh = img->height * factor;
  FpImage *scaled = fp_image_new (nw, nh);

  scaled->flags = img->flags | FPI_IMAGE_PARTIAL;
  scaled->ppmm = img->ppmm;
  for (guint y = 0; y < nh; ++y)
    {
      const guint sy = y / factor;
      for (guint x = 0; x < nw; ++x)
        scaled->data[y * nw + x] = img->data[sy * img->width + (x / factor)];
    }
  return scaled;
}

static void
scan5125_data_free (gpointer data)
{
  g_free (data);
}

// Build the second FDT switch payload from the first switch's reply, mirroring
// fdt_construct_payload() in exp5125_v2.py. The callback data is the protocol
// payload (data only), which is what reply1 is in the Python reference, so
// data[4+i] == HELP[11+i].
static void
fdt_construct_payload (guint8 *buf, const guint8 *first_reply, guint16 reply_len)
{
  guint8 help_buf[32] = {0};
  guint16 n = MIN (reply_len, 32);

  memcpy (help_buf, first_reply, n);
  for (int i = 0; i < 12; i += 2)
    {
      guint16 value = help_buf[4 + i] | (help_buf[5 + i] << 8);

      value >>= 1;
      buf[2 + i] = 0x80;
      buf[2 + i + 1] = value & 0xFF;
    }
}

static void
scan5125_on_fdt_switch_1 (FpDevice *dev, guint8 *data, guint16 len,
                          gpointer ssm, GError *error)
{
  Scan5125Data *d = fpi_ssm_get_data (ssm);

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  d->reply1_len = MIN (len, sizeof (d->reply1));
  memcpy (d->reply1, data, d->reply1_len);
  fp_dbg ("FDT switch 1 reply: %u bytes", len);
  fpi_ssm_next_state (ssm);
}

static void
scan5125_on_dac_write (FpDevice *dev, gpointer ssm, GError *error)
{
  FpiDeviceGoodixTls5125 *self = FPI_DEVICE_GOODIXTLS5125 (dev);
  Scan5125Data *d = fpi_ssm_get_data (ssm);

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (++d->dac_writes_done >= 4)
    {
      fp_dbg ("DAC registers written from OTP");
      fpi_ssm_next_state (ssm);
      return;
    }

  // Chain the remaining DAC register writes, in WBDI order: 0x0220 (dac,
  // otp[46]<<4|8), 0x0236 (dac1, otp[47]), 0x0238 (dac2, otp[48]), 0x023a
  // (dac3, otp[49]). Verified byte-for-byte against WBDI "from otp dac 0xb78,
  // dac1 0xb9, dac2 0xb7, dac3 0xb7".
  switch (d->dac_writes_done)
    {
    case 1:
      goodix_send_write_sensor_register (dev, 0x0236, self->otp[47],
                                         scan5125_on_dac_write, ssm);
      break;
    case 2:
      goodix_send_write_sensor_register (dev, 0x0238, self->otp[48],
                                         scan5125_on_dac_write, ssm);
      break;
    case 3:
      goodix_send_write_sensor_register (dev, 0x023a, self->otp[49],
                                         scan5125_on_dac_write, ssm);
      break;
    }
}

static void
scan5125_on_read_img (FpDevice *dev, guint8 *data, guint16 len,
                      gpointer ssm, GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);

  // No calibration image exists for the 5125, so no linear_subtract_inplace.

  // Debug: raw TLS payload lands in fprintd PrivateTmp (/proc/<pid>/root/tmp).
  if (g_getenv ("GOODIX_5125_DUMP_RAW"))
    {
      FILE *f = fopen ("/tmp/5125_raw.bin", "wb");
      if (f)
        {
          fwrite (data, 1, len, f);
          fclose (f);
          fp_dbg ("dumped raw TLS payload (%u bytes) to /tmp/5125_raw.bin", len);
        }
    }

  GoodixTls5xxPix *raw_frame = calloc (GOODIX5125_SCAN_WIDTH * GOODIX5125_HEIGHT,
                                       sizeof (GoodixTls5xxPix));
  goodixtls5xx_decode_frame (raw_frame, len, data);
  guint8 *squashed = calloc (GOODIX5125_SCAN_WIDTH * GOODIX5125_HEIGHT, 1);
  goodixtls5xx_squash_frame_linear (raw_frame, squashed,
                                    GOODIX5125_SCAN_WIDTH * GOODIX5125_HEIGHT);
  free (raw_frame);

  FpImage *img = crop_frame (squashed);
  free (squashed);

  if (g_getenv ("GOODIX_5125_DUMP_PGM"))
    {
      FILE *f = fopen ("/tmp/5125_drv_frame.pgm", "wb");
      if (f)
        {
          fprintf (f, "P5\n%d %d\n255\n", img->width, img->height);
          fwrite (img->data, 1, img->width * img->height, f);
          fclose (f);
          fp_dbg ("dumped driver frame to /tmp/5125_drv_frame.pgm");
        }
    }

  // 64x80 is too small for stable NBIS minutiae; NN-upscale preserves the
  // ~6px ridge edges (bilinear flattens them and NBIS finds 0 minutiae).
  FpImage *scaled = goodix5125_upscale_nn (img);
  g_object_unref (img);

  fpi_image_device_image_captured (img_dev, scaled);
  fpi_ssm_next_state (ssm);
}

static void
scan5125_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);
  Scan5125Data *d = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN5125_QUERY_MCU:
      goodix_send_query_mcu_state (dev, goodixtls5xx_check_none_cmd, ssm);
      break;

    case SCAN5125_FDT_SWITCH_1:
      goodix_send_mcu_switch_to_fdt_mode (dev, fdt_switch_state_mode,
                                          sizeof (fdt_switch_state_mode),
                                          NULL, scan5125_on_fdt_switch_1, ssm);
      break;

    case SCAN5125_NAV:
      goodix_send_nav_0 (dev, goodixtls5xx_check_none_cmd, ssm);
      break;

    case SCAN5125_FDT_SWITCH_2:
      {
        guint8 payload[sizeof (fdt_switch_state_mode)];

        memcpy (payload, fdt_switch_state_mode, sizeof (payload));
        fdt_construct_payload (payload, d->reply1, d->reply1_len);
        goodix_send_mcu_switch_to_fdt_mode (dev, payload, sizeof (payload),
                                            NULL, goodixtls5xx_check_none_cmd, ssm);
      }
      break;

    case SCAN5125_READ_REG:
      goodix_send_read_sensor_register (dev, 0x0082, 2,
                                        goodixtls5xx_check_none_cmd, ssm);
      break;

    case SCAN5125_WRITE_DAC:
      {
        FpiDeviceGoodixTls5125 *self = FPI_DEVICE_GOODIXTLS5125 (dev);

        if (self->otp_len < 50)
          {
            fpi_ssm_mark_failed (ssm, g_error_new (G_IO_ERROR,
                                                   G_IO_ERROR_INVALID_DATA,
                                                   "OTP dump too short (%u) "
                                                   "for DAC calibration",
                                                   self->otp_len));
            break;
          }
        d->dac_writes_done = 0;
        goodix_send_write_sensor_register (dev, 0x0220,
                                           (self->otp[46] << 4) | 8,
                                           scan5125_on_dac_write, ssm);
      }
      break;

    case SCAN5125_GET_IMG:
      fpi_image_device_report_finger_status (img_dev, TRUE);
      goodix_tls_read_image_timeout (dev, GOODIX5125_GET_IMG_TIMEOUT_MS,
                                     scan5125_on_read_img, ssm);
      break;

    case SCAN5125_DONE:
      fpi_image_device_report_finger_status (img_dev, FALSE);
      fpi_ssm_next_state (ssm);
      break;
    }
}

static void
scan5125_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    {
      fp_err ("failed to scan: %s (code: %d)", error->message, error->code);
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  fp_dbg ("finished scan");
}

static void
scan5125_start (FpDevice *dev)
{
  Scan5125Data *d = g_new0 (Scan5125Data, 1);
  FpiSsm *ssm = fpi_ssm_new (dev, scan5125_run_state, SCAN5125_NUM_STATES);

  fpi_ssm_set_data (ssm, d, scan5125_data_free);
  fpi_ssm_start (ssm, scan5125_complete);
}

static void
scan5125_change_state (FpImageDevice *img_dev, FpiImageDeviceState state)
{
  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    scan5125_start (FP_DEVICE (img_dev));
}

static GoodixTls5xxMcuConfig
get_mcu_config (void)
{
  GoodixTls5xxMcuConfig cfg;

  cfg.free_fn = NULL;
  cfg.data = fdt_switch_state_mode;
  cfg.data_len = sizeof (fdt_switch_state_mode);
  return cfg;
}

// ---- PSK loading from disk (like 5F10) -------------------------------------------

static gboolean
load_secrets (FpiDeviceGoodixTls5125 *self, GError **error)
{
  const gchar *psk_path = g_getenv (GOODIX_5125_PSK_FILE_ENV);
  g_autofree gchar *data = NULL;
  gsize length = 0;
  g_autoptr (GError) inner = NULL;

  if (!psk_path) psk_path = GOODIX_5125_DEFAULT_PSK_FILE;

  if (!g_file_get_contents (psk_path, &data, &length, &inner) ||
      length != GOODIX_5125_PSK_LEN)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "goodixtls5125: failed to load TLS-PSK from \"%s\" (%s). "
                   "Provide the %d-byte raw TLS-PSK for the sensor's current "
                   "pairing at that path, or set %s to the correct file.",
                   psk_path,
                   inner ? inner->message : "wrong file length",
                     GOODIX_5125_PSK_LEN,
                   GOODIX_5125_PSK_FILE_ENV);
      return FALSE;
    }
  self->tls_psk = g_memdup (data, GOODIX_5125_PSK_LEN);
  return TRUE;
}

static void
dev_open (FpDevice *dev);

static void
dev_close (FpDevice *dev);

static void
dev_open (FpDevice *dev)
{
  FpiDeviceGoodixTls5125 *self = FPI_DEVICE_GOODIXTLS5125 (dev);
  GError *error = NULL;

  if (!load_secrets (self, &error))
    {
      fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
      return;
    }

  if (!goodix_dev_init (dev, &error))
    {
      fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  // Feed the per-device TLS session PSK to the OpenSSL server callback.
  goodix_tls_set_psk (self->tls_psk, GOODIX_5125_PSK_LEN);

  fpi_ssm_start (fpi_ssm_new (dev, activate_run_state, ACTIVATE_NUM_STATES),
                 activate_complete);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceGoodixTls5125 *self = FPI_DEVICE_GOODIXTLS5125 (dev);
  GError *error = NULL;

  g_clear_pointer (&self->tls_psk, g_free);

  goodix_reset_state (dev);
  goodix_shutdown_tls (dev, &error);
  goodix_dev_deinit (dev, &error);

  fpi_image_device_close_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
dev_deactivate (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);

  goodix_reset_state (dev);

  // NOTE: TLS is NOT shut down here. The 5125 delivers its image data
  // TLS-encrypted over the same channel that carried the handshake, so the
  // TLS session must survive across scan sessions. The inherited 5xx
  // dev_deactivate() calls goodix_shutdown_tls(), which frees priv->tls_hop
  // and SIGSEGVs the next goodix_tls_ready_image_handler(). Shutdown happens
  // only in dev_close().

  FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS (dev);
  goodixtls5xx_cleanup (FPI_DEVICE_GOODIXTLS5XX (dev));

  if (cls->reset_state)
    cls->reset_state (dev);
  fpi_image_device_deactivate_complete (img_dev, NULL);
}

static void
fpi_device_goodixtls5125_class_init (FpiDeviceGoodixTls5125Class *class)
{
  FpiDeviceGoodixTlsClass *gx_class = FPI_DEVICE_GOODIXTLS_CLASS (class);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (class);
  FpImageDeviceClass *img_dev_class = FP_IMAGE_DEVICE_CLASS (class);
  FpiDeviceGoodixTls5xxClass *xx_cls = FPI_DEVICE_GOODIXTLS5XX_CLASS (class);

  xx_cls->get_mcu_cfg = get_mcu_config;
  xx_cls->process_frame = crop_frame;
  xx_cls->scan_height = GOODIX5125_HEIGHT;
  xx_cls->scan_width = GOODIX5125_SCAN_WIDTH;
  xx_cls->psk = NULL;  // per-device, loaded from disk
  xx_cls->psk_flags = GOODIX_5125_PSK_FLAGS;
  xx_cls->psk_len = GOODIX_5125_PSK_LEN;
  xx_cls->firmware_version = GOODIX_5125_FIRMWARE_VERSION;
  xx_cls->reset_number = GOODIX_5125_RESET_NUMBER;

  gx_class->interface = GOODIX_5125_INTERFACE;
  gx_class->ep_in = GOODIX_5125_EP_IN;
  gx_class->ep_out = GOODIX_5125_EP_OUT;

  dev_class->id = "goodixtls5125";
  dev_class->full_name = "Goodix TLS Fingerprint Sensor 5125";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = 20;

  // TODO: characterize FAR/FRR and tune threshold
  img_dev_class->bz3_threshold = 24;
  img_dev_class->img_width = GOODIX5125_CROP_WIDTH;
  img_dev_class->img_height = GOODIX5125_HEIGHT;

  // Override open/close to load per-device PSK before goodix_tls_init
  dev_class->open = dev_open;
  dev_class->close = dev_close;

  // The 5125 needs its own scan SSM (FDT switch x2 + prebulk), not the 5xx
  // calibration-based one.
  img_dev_class->change_state = scan5125_change_state;
  // Keep the TLS channel alive across scan sessions (image data is TLS-encrypted);
  // shutdown happens only in dev_close(). Overrides the 5xx deactivate.
  img_dev_class->deactivate = dev_deactivate;

  fpi_device_class_auto_initialize_features (dev_class);
}

static void
fpi_device_goodixtls5125_init (FpiDeviceGoodixTls5125 *self)
{
}
