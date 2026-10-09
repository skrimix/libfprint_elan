/*
 * ELAN 04f3:0c28 driver using ELAN's own matching engine
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * The 96x96 0c28 is a press sensor that the swipe-oriented elan driver cannot
 * match reliably. This driver captures single touches (see
 * examples/elan-oem/capture.py) and enrolls and verifies them with
 * EngineAdapter.dll from ELAN's Windows driver 1.1.0.2111, loaded in-process
 * by elan_oem_engine.c. The engine's template is stored as an opaque print.
 */

#define FP_COMPONENT "elan_oem"

#include "drivers_api.h"
#include "elan_oem_engine.h"

#define ENGINE_DLL_DEFAULT "/usr/lib/libfprint-2/elan_oem/EngineAdapter.dll"
#define ENGINE_DLL_SHA256 "8f9254d10594ff7479741e72d22abec9417807257ac0c7a967ec7eaa8865a9e9"

#define EP_CMD_OUT (0x1 | FPI_USB_ENDPOINT_OUT)
#define EP_CMD_IN (0x3 | FPI_USB_ENDPOINT_IN)
#define EP_IMG_IN (0x2 | FPI_USB_ENDPOINT_IN)
#define CMD_TIMEOUT 10000

#define FRAME_SIZE ELAN_ENGINE_FRAME_SIZE
#define CALIBRATION_ROUNDS 10
#define CALIBRATION_STATUS_POLLS 30
#define CALIBRATION_MAX_DELTA 500
/* The firmware reports a finger even on an empty sensor, so a finger is
 * present when the 90th percentile of the background-subtracted frame exceeds
 * this. Tuned for this reader, not an OEM quality check. */
#define PRESENCE_THRESHOLD 500
#define POLL_INTERVAL 80
/* The first frame of a touch is often taken while pressing down, so enrollment
 * uses frame 2 (about 0.4 s of contact), and matching tries frames 2 to 4 as
 * they arrive until one matches or the finger is lifted. */
#define FIRST_USED_FRAME 2
#define LAST_MATCH_FRAME 4

/* Commands from elan.h */
typedef struct
{
  guint8 cmd[2];
  guint8 ep;
  gsize  len;
} ElanOemCmd;

static const ElanOemCmd get_fw_ver_cmd = { { 0x40, 0x19 }, EP_CMD_IN, 2 };
static const ElanOemCmd get_sensor_dim_cmd = { { 0x00, 0x0c }, EP_CMD_IN, 4 };
static const ElanOemCmd get_image_cmd = { { 0x00, 0x09 }, EP_IMG_IN, FRAME_SIZE * 2 };
static const ElanOemCmd get_calib_status_cmd = { { 0x40, 0x23 }, EP_CMD_IN, 1 };
static const ElanOemCmd get_calib_mean_cmd = { { 0x40, 0x24 }, EP_CMD_IN, 2 };
static const ElanOemCmd led_on_cmd = { { 0x40, 0x31 }, EP_CMD_IN, 0 };
static const ElanOemCmd pre_scan_cmd = { { 0x40, 0x3f }, EP_CMD_IN, 1 };
static const ElanOemCmd stop_cmd = { { 0x00, 0x0b }, EP_CMD_IN, 0 };

struct _FpiDeviceElanOem
{
  FpDevice          parent;

  const ElanOemCmd *cmd;
  guint             cmd_timeout;
  gboolean          cmd_never_cancel;
  guint8           *last_read;

  guint16           background[FRAME_SIZE];
  gint              calib_rounds_left;
  gint              calib_polls_left;
  gboolean          calib_busy;

  guint             touch_frames; /* consecutive frames with a finger */
  gboolean          touch_done;   /* this touch was handled, wait for a lift */
  guint             bad_frames;   /* frames of this touch the engine rejected */
  guint8            frame[FRAME_SIZE];

  guint             enroll_stage;
  GPtrArray        *templates; /* GBytes for each print to verify or identify */

  /* Results reported once the sensor is stopped */
  GError           *error;
  FpPrint          *enrolled;
  FpiMatchResult    match;
  guint             match_index; /* into templates */
  GError           *retry;
};

G_DECLARE_FINAL_TYPE (FpiDeviceElanOem, fpi_device_elan_oem, FPI, DEVICE_ELAN_OEM, FpDevice);
G_DEFINE_TYPE (FpiDeviceElanOem, fpi_device_elan_oem, FP_TYPE_DEVICE);

static void
cmd_read_cb (FpiUsbTransfer *transfer, FpDevice *dev,
             gpointer user_data, GError *error)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  g_free (self->last_read);
  self->last_read = g_memdup2 (transfer->buffer, transfer->actual_length);
  fpi_ssm_next_state (transfer->ssm);
}

static void
cmd_write_cb (FpiUsbTransfer *transfer, FpDevice *dev,
              gpointer user_data, GError *error)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);
  FpiUsbTransfer *read;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  if (!self->cmd->len)
    {
      fpi_ssm_next_state (transfer->ssm);
      return;
    }

  read = fpi_usb_transfer_new (dev);
  read->ssm = transfer->ssm;
  read->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk (read, self->cmd->ep, self->cmd->len);
  fpi_usb_transfer_submit (read, self->cmd_timeout,
                           self->cmd_never_cancel ? NULL : fpi_device_get_cancellable (dev),
                           cmd_read_cb, NULL);
}

/* Sends a command and reads its response into last_read; timeout 0 waits forever. */
static void
run_cmd (FpiSsm *ssm, FpDevice *dev, const ElanOemCmd *cmd, guint timeout)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  self->cmd = cmd;
  self->cmd_timeout = timeout;
  self->cmd_never_cancel = cmd == &stop_cmd;

  transfer->ssm = ssm;
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (transfer, EP_CMD_OUT, (guint8 *) cmd->cmd,
                                   sizeof cmd->cmd, NULL);
  fpi_usb_transfer_submit (transfer, CMD_TIMEOUT,
                           self->cmd_never_cancel ? NULL : fpi_device_get_cancellable (dev),
                           cmd_write_cb, NULL);
}

static guint16
pixel (const guint8 *raw, int i)
{
  return GUINT16_FROM_LE (((const guint16 *) raw)[i]);
}

static int
cmp_u16 (const void *a, const void *b)
{
  return (int) *(const guint16 *) a - (int) *(const guint16 *) b;
}

/* Subtracts the background from the last frame. If a finger is present,
 * returns TRUE and stretches the result linearly to 8 bits into frame. */
static gboolean
process_frame (FpiDeviceElanOem *self)
{
  g_autofree guint16 *signal = g_new (guint16, FRAME_SIZE);
  g_autofree guint16 *sorted = NULL;
  guint16 lo = G_MAXUINT16, hi = 0;

  for (int i = 0; i < FRAME_SIZE; i++)
    {
      guint16 px = pixel (self->last_read, i);

      signal[i] = px > self->background[i] ? px - self->background[i] : 0;
      lo = MIN (lo, signal[i]);
      hi = MAX (hi, signal[i]);
    }

  sorted = g_memdup2 (signal, FRAME_SIZE * sizeof *signal);
  qsort (sorted, FRAME_SIZE, sizeof *sorted, cmp_u16);
  if (sorted[FRAME_SIZE * 9 / 10] <= PRESENCE_THRESHOLD)
    return FALSE;

  for (int i = 0; i < FRAME_SIZE; i++)
    self->frame[i] = (signal[i] - lo) * 255 / MAX (hi - lo, 1);
  return TRUE;
}

/* Enroll: feed the frame to the engine. Returns TRUE when enrollment is done. */
static gboolean
enroll_touch (FpiDeviceElanOem *self, FpiSsm *ssm)
{
  FpDevice *dev = FP_DEVICE (self);
  g_autofree guint8 *tmpl = NULL;
  size_t len = 0;
  FpPrint *print = NULL;

  switch (elan_engine_enroll_add (self->frame))
    {
    case ELAN_ENGINE_MORE:
      fpi_device_enroll_progress (dev, ++self->enroll_stage, NULL, NULL);
      return FALSE;

    case ELAN_ENGINE_BAD:
      fpi_device_enroll_progress (dev, self->enroll_stage, NULL,
                                  fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
      return FALSE;

    case ELAN_ENGINE_DONE:
      if (elan_engine_enroll_commit (&tmpl, &len))
        break;
      fpi_device_get_enroll_data (dev, &print);
      fpi_print_set_type (print, FPI_PRINT_RAW);
      g_object_set (print, "fpi-data",
                    g_variant_new ("(@ay)",
                                   g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, tmpl, len, 1)),
                    NULL);
      fp_info ("Enrolled with a %zu-byte template", len);
      self->enrolled = g_object_ref (print);
      fpi_ssm_mark_completed (ssm);
      return TRUE;
    }

  fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                      "ELAN engine enrollment failed"));
  return TRUE;
}

/* Verify and identify: compares the frame with each template.
 * Returns TRUE when done, after a match or an engine error. */
static gboolean
match_frame (FpiDeviceElanOem *self, FpiSsm *ssm)
{
  int r = elan_engine_accept (self->frame);

  for (guint i = 0; !r && i < self->templates->len; i++)
    {
      gsize len;
      const guint8 *tmpl = g_bytes_get_data (g_ptr_array_index (self->templates, i), &len);

      r = elan_engine_verify (tmpl, len);
      if (r == 1)
        {
          fp_info ("Frame %u matched print %u", self->touch_frames, i);
          self->match = FPI_MATCH_SUCCESS;
          self->match_index = i;
          fpi_ssm_mark_completed (ssm);
          return TRUE;
        }
    }
  if (r < 0)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "ELAN engine verification failed"));
      return TRUE;
    }
  if (r == ELAN_ENGINE_BAD)
    self->bad_frames++;
  return FALSE;
}

/* No frame of the touch matched; retry if the engine rejected all of them. */
static void
match_failed (FpiDeviceElanOem *self, FpiSsm *ssm)
{
  fp_info ("No match in %u frames", self->touch_frames - 1);
  self->match = FPI_MATCH_FAIL;
  if (self->bad_frames == self->touch_frames - 1)
    {
      self->match = FPI_MATCH_ERROR;
      self->retry = fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);
    }
  fpi_ssm_mark_completed (ssm);
}

enum capture_states {
  CAPTURE_GET_BACKGROUND,
  CAPTURE_GET_MEAN,
  CAPTURE_CHECK_MEAN,
  CAPTURE_GET_CALIB_STATUS,
  CAPTURE_CHECK_CALIB_STATUS,
  CAPTURE_LED_ON,
  CAPTURE_WAIT_FINGER,
  CAPTURE_GET_IMAGE,
  CAPTURE_PROCESS_IMAGE,
  CAPTURE_NUM_STATES,
};

static void
capture_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);
  gboolean is_enroll = fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL;
  guint32 bg_mean = 0;
  guint16 calib_mean;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    /* Calibration as in elan.c, with the sensor clear */
    case CAPTURE_GET_BACKGROUND:
      run_cmd (ssm, dev, &get_image_cmd, CMD_TIMEOUT);
      break;

    case CAPTURE_GET_MEAN:
      for (int i = 0; i < FRAME_SIZE; i++)
        self->background[i] = pixel (self->last_read, i);
      run_cmd (ssm, dev, &get_calib_mean_cmd, CMD_TIMEOUT);
      break;

    case CAPTURE_CHECK_MEAN:
      calib_mean = self->last_read[0] << 8 | self->last_read[1];
      for (int i = 0; i < FRAME_SIZE; i++)
        bg_mean += self->background[i];
      bg_mean /= FRAME_SIZE;
      fp_dbg ("Background mean %u, calibration mean %u", bg_mean, calib_mean);
      if (ABS ((gint) bg_mean - calib_mean) <= CALIBRATION_MAX_DELTA)
        {
          fpi_ssm_jump_to_state (ssm, CAPTURE_LED_ON);
        }
      else if (--self->calib_rounds_left <= 0)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                              "Background did not settle after calibration"));
        }
      else
        {
          self->calib_polls_left = CALIBRATION_STATUS_POLLS;
          self->calib_busy = FALSE;
          fpi_ssm_next_state (ssm);
        }
      break;

    case CAPTURE_GET_CALIB_STATUS:
      run_cmd (ssm, dev, &get_calib_status_cmd, CMD_TIMEOUT);
      break;

    case CAPTURE_CHECK_CALIB_STATUS:
      /* Wait for the status to go busy (0x01) and then done (0x03). */
      self->calib_busy |= self->last_read[0] == 0x01;
      if (self->calib_busy && self->last_read[0] == 0x03)
        fpi_ssm_jump_to_state (ssm, CAPTURE_GET_BACKGROUND);
      else if (--self->calib_polls_left > 0)
        fpi_ssm_jump_to_state_delayed (ssm, CAPTURE_GET_CALIB_STATUS, 50);
      else
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                            "Calibration did not complete"));
      break;

    case CAPTURE_LED_ON:
      fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NEEDED,
                                               FP_FINGER_STATUS_NONE);
      run_cmd (ssm, dev, &led_on_cmd, CMD_TIMEOUT);
      break;

    case CAPTURE_WAIT_FINGER:
      run_cmd (ssm, dev, &pre_scan_cmd, 0);
      break;

    case CAPTURE_GET_IMAGE:
      if (self->last_read[0] != 0x55)
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "Unexpected finger status 0x%02x",
                                                            self->last_read[0]));
      else
        run_cmd (ssm, dev, &get_image_cmd, CMD_TIMEOUT);
      break;

    case CAPTURE_PROCESS_IMAGE:
      if (!process_frame (self))
        {
          if (self->touch_frames)
            fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NONE,
                                                     FP_FINGER_STATUS_PRESENT);
          if (self->touch_frames >= FIRST_USED_FRAME && !self->touch_done)
            {
              /* Lifted while matching */
              match_failed (self, ssm);
              return;
            }
          if (self->touch_frames && !self->touch_done)
            {
              GError *retry = fpi_device_retry_new (FP_DEVICE_RETRY_TOO_SHORT);

              fp_dbg ("Touch too short");
              if (!is_enroll)
                {
                  self->match = FPI_MATCH_ERROR;
                  self->retry = retry;
                  fpi_ssm_mark_completed (ssm);
                  return;
                }
              fpi_device_enroll_progress (dev, self->enroll_stage, NULL, retry);
            }
          self->touch_frames = 0;
          self->touch_done = FALSE;
        }
      else if (!self->touch_done && ++self->touch_frames == 1)
        {
          fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_PRESENT,
                                                   FP_FINGER_STATUS_NONE);
        }
      else if (!self->touch_done && is_enroll)
        {
          self->touch_done = TRUE;
          if (enroll_touch (self, ssm))
            return;
        }
      else if (!self->touch_done)
        {
          if (match_frame (self, ssm))
            return;
          if (self->touch_frames == LAST_MATCH_FRAME)
            {
              match_failed (self, ssm);
              return;
            }
        }
      fpi_ssm_jump_to_state_delayed (ssm, CAPTURE_WAIT_FINGER, POLL_INTERVAL);
      break;
    }
}

static void
report_match (FpDevice *dev)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);
  GPtrArray *prints = NULL;

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    {
      fpi_device_verify_report (dev, self->match, NULL, g_steal_pointer (&self->retry));
      return;
    }
  fpi_device_get_identify_data (dev, &prints);
  fpi_device_identify_report (dev,
                              self->match == FPI_MATCH_SUCCESS ?
                              g_ptr_array_index (prints, self->match_index) : NULL,
                              NULL, g_steal_pointer (&self->retry));
}

static void
complete_match (FpDevice *dev, GError *error)
{
  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_complete (dev, error);
  else
    fpi_device_identify_complete (dev, error);
}

static void
stop_run_state (FpiSsm *ssm, FpDevice *dev)
{
  run_cmd (ssm, dev, &stop_cmd, CMD_TIMEOUT);
}

static void
stop_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);

  /* The result is already known, so failing to stop only gets logged. */
  if (error)
    fp_warn ("Failed to stop the sensor: %s", error->message);
  g_clear_error (&error);

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL)
    {
      fpi_device_enroll_complete (dev, self->error ? NULL : g_steal_pointer (&self->enrolled),
                                  g_steal_pointer (&self->error));
      g_clear_object (&self->enrolled);
      return;
    }

  if (!self->error)
    report_match (dev);
  g_clear_error (&self->retry);
  g_clear_pointer (&self->templates, g_ptr_array_unref);
  complete_match (dev, g_steal_pointer (&self->error));
}

static void
capture_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);

  /* Always stop the sensor, also after errors and cancellation. */
  self->error = error;
  fpi_ssm_start (fpi_ssm_new (dev, stop_run_state, 1), stop_complete);
}

static void
start_capture (FpDevice *dev)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);

  self->calib_rounds_left = CALIBRATION_ROUNDS;
  self->touch_frames = 0;
  self->touch_done = FALSE;
  self->bad_frames = 0;
  self->match = FPI_MATCH_ERROR;
  fpi_ssm_start (fpi_ssm_new (dev, capture_run_state, CAPTURE_NUM_STATES), capture_complete);
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);

  self->enroll_stage = 0;
  if (elan_engine_enroll_begin ())
    {
      fpi_device_enroll_complete (dev, NULL,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                            "ELAN engine enrollment failed"));
      return;
    }
  start_capture (dev);
}

/* Loads the engine templates of the prints and starts capturing. */
static void
start_match (FpDevice *dev, GPtrArray *prints)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);

  self->templates = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  for (guint i = 0; i < prints->len; i++)
    {
      g_autoptr(GVariant) data = NULL;
      g_autoptr(GVariant) blob = NULL;

      g_object_get (g_ptr_array_index (prints, i), "fpi-data", &data, NULL);
      if (!data || !g_variant_check_format_string (data, "(@ay)", FALSE))
        {
          g_clear_pointer (&self->templates, g_ptr_array_unref);
          complete_match (dev, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
          return;
        }
      g_variant_get (data, "(@ay)", &blob);
      g_ptr_array_add (self->templates, g_variant_get_data_as_bytes (blob));
    }
  start_capture (dev);
}

static void
dev_verify (FpDevice *dev)
{
  g_autoptr(GPtrArray) prints = g_ptr_array_new ();
  FpPrint *print = NULL;

  fpi_device_get_verify_data (dev, &print);
  g_ptr_array_add (prints, print);
  start_match (dev, prints);
}

static void
dev_identify (FpDevice *dev)
{
  GPtrArray *prints = NULL;

  fpi_device_get_identify_data (dev, &prints);
  start_match (dev, prints);
}

enum open_states {
  OPEN_GET_FW_VER,
  OPEN_GET_SENSOR_DIM,
  OPEN_CHECK_SENSOR_DIM,
  OPEN_NUM_STATES,
};

static void
open_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_GET_FW_VER:
      run_cmd (ssm, dev, &get_fw_ver_cmd, CMD_TIMEOUT);
      break;

    case OPEN_GET_SENSOR_DIM:
      fp_dbg ("Firmware %02x%02x", self->last_read[0], self->last_read[1]);
      run_cmd (ssm, dev, &get_sensor_dim_cmd, CMD_TIMEOUT);
      break;

    case OPEN_CHECK_SENSOR_DIM:
      if (self->last_read[0] != ELAN_ENGINE_WIDTH || self->last_read[1] != 0 ||
          self->last_read[2] != ELAN_ENGINE_HEIGHT || self->last_read[3] != 0)
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                            "Unexpected sensor dimensions"));
      else
        fpi_ssm_next_state (ssm);
      break;
    }
}

static void
open_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    {
      elan_engine_close ();
      g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, NULL);
    }
  fpi_device_open_complete (dev, error);
}

/* The engine's Windows shims only cover this build, so refuse anything else. */
static gboolean
check_engine (const char *path, GError **error)
{
  g_autofree gchar *contents = NULL;
  g_autofree gchar *sha256 = NULL;
  gsize len;

  if (!g_file_get_contents (path, &contents, &len, error))
    return FALSE;
  sha256 = g_compute_checksum_for_data (G_CHECKSUM_SHA256, (const guchar *) contents, len);
  if (g_strcmp0 (sha256, ENGINE_DLL_SHA256) != 0)
    {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_INVAL,
                   "%s is not ELAN's EngineAdapter.dll 1.1.0.2111", path);
      return FALSE;
    }
  return TRUE;
}

static void
dev_open (FpDevice *dev)
{
  const char *path = g_getenv ("ELAN_OEM_ENGINE_DLL");
  g_autoptr(GError) engine_error = NULL;
  GError *error = NULL;

  if (!path)
    path = ENGINE_DLL_DEFAULT;
  if (!check_engine (path, &engine_error) || elan_engine_open (path))
    {
      fpi_device_open_complete (dev, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                               "Cannot load ELAN matching engine (set ELAN_OEM_ENGINE_DLL): %s",
                                                               engine_error ? engine_error->message : path));
      return;
    }

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (dev), 0, 0, &error))
    {
      elan_engine_close ();
      fpi_device_open_complete (dev, error);
      return;
    }
  fpi_ssm_start (fpi_ssm_new (dev, open_run_state, OPEN_NUM_STATES), open_complete);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceElanOem *self = FPI_DEVICE_ELAN_OEM (dev);
  GError *error = NULL;

  elan_engine_close ();
  g_clear_pointer (&self->last_read, g_free);
  g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, &error);
  fpi_device_close_complete (dev, error);
}

static const FpIdEntry id_table[] = {
  { .vid = 0x04f3, .pid = 0x0c28 },
  { .vid = 0, .pid = 0 },
};

static void
fpi_device_elan_oem_init (FpiDeviceElanOem *self)
{
}

static void
fpi_device_elan_oem_class_init (FpiDeviceElanOemClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "ELAN Fingerprint Sensor (OEM matcher)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = 18; /* the engine decides, 18 touches in testing */
  dev_class->temp_hot_seconds = -1;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  dev_class->identify = dev_identify;

  fpi_device_class_auto_initialize_features (dev_class);
}
