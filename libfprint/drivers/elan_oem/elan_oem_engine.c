// SPDX-License-Identifier: LGPL-2.1-or-later
// Drives ELAN's WinBio engine interface (attach, enroll, commit, verify, detach)
// with stub sensor and storage adapters. No GLib, so examples/elan-oem/probe
// links it as well.
#include "pe-loader.c"
#include "elan_oem_engine.h"

#define SUBFACTOR 1 // the single enrolled finger

#define WINBIO_I_MORE_DATA 0x00090001
#define WINBIO_E_NO_MATCH 0x80098005
#define WINBIO_E_BAD_CAPTURE 0x80098008
#define WINBIO_E_DATABASE_NO_RESULTS 0x8009801f
#define WINBIO_E_DATABASE_NO_MORE_RECORDS 0x80098020
#define WINBIO_PURPOSE_VERIFY 1
#define WINBIO_PURPOSE_ENROLL 4

// WINBIO_IDENTITY of type WINBIO_ID_TYPE_SID holding S-1-5.
static u8 identity[76] = {3, 0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5};
static u8 template_data[1024 * 1024];
static u64 template_size;

// Sensor adapter: only the ELAN GET_SENSOR_DIMENSIONS control (from WbfUsbDriver.dll).
static u32 MS sensor_control(void *pipeline, u32 code, void *send, u64 send_size, void *receive,
                             u64 receive_size, u64 *received, u32 *status) {
  if (code != 0x442080 || receive_size != 8) {
    fprintf(stderr, "Unexpected sensor control %#x (output size %lu)\n", code, receive_size);
    abort();
  }
  ((u32 *)receive)[0] = ELAN_ENGINE_WIDTH;
  ((u32 *)receive)[1] = ELAN_ENGINE_HEIGHT;
  *received = 8;
  *status = 0;
  return 0;
}

static u32 MS unsupported_callback(void) {
  fprintf(stderr, "Unimplemented WinBio adapter callback\n");
  abort();
}

// Storage adapter: a single in-memory record. Records are WINBIO_STORAGE_RECORD:
// identity at 0x00, subfactor at 0x08, template blob/size at 0x20/0x28.
static u32 MS add_record(void *pipeline, u8 *record) {
  u64 size = *(u64 *)(record + 0x28);
  if (!size || size > sizeof template_data)
    abort();
  memcpy(template_data, *(void **)(record + 0x20), size);
  template_size = size;
  return 0;
}
static u32 MS delete_record(void *pipeline, void *id, u8 subfactor) {
  template_size = 0;
  return 0;
}
static u32 MS query_by_subject(void *pipeline, void *id, u8 subfactor) {
  return template_size && subfactor == SUBFACTOR && !memcmp(id, identity, sizeof identity)
             ? 0
             : WINBIO_E_DATABASE_NO_RESULTS;
}
static u32 MS first_record(void *pipeline) {
  return template_size ? 0 : WINBIO_E_DATABASE_NO_RESULTS;
}
static u32 MS next_record(void *pipeline) { return WINBIO_E_DATABASE_NO_MORE_RECORDS; }
static u32 MS get_current_record(void *pipeline, u8 *record) {
  memset(record, 0, 64);
  *(void **)record = identity;
  record[0x08] = SUBFACTOR;
  *(void **)(record + 0x20) = template_data;
  *(u64 *)(record + 0x28) = template_size;
  return 0;
}

static u32(MS *attach)(void *);
static u32(MS *detach)(void *);
static u32(MS *accept_sample)(void *, void *, u64, u8, u32 *);
static u32(MS *verify)(void *, void *, u8, u8 *, void **, u64 *, void **, u64 *, u32 *);
static u32(MS *create_enrollment)(void *);
static u32(MS *update_enrollment)(void *, u32 *);
static u32(MS *enrollment_status)(void *, u32 *);
static u32(MS *commit_enrollment)(void *, void *, u8, void *, u64);

// Adapter interface tables, indexed by byte offset of each method.
static void *sensor[64], *storage[64];
// WINBIO_PIPELINE; the engine stores its context in it during attach.
static void *pipeline[128];
// WINBIO_BIR: a WINBIO_BIR_HEADER followed by an ANSI 381 standard data block.
static u8 bir[0x80 + ELAN_ENGINE_FRAME_SIZE];

static int fail(const char *what, u32 hr) {
  fprintf(stderr, "ELAN engine: %s failed: %#x\n", what, hr);
  return ELAN_ENGINE_ERROR;
}

static int load(const char *dll_path) {
  if (load_pe(dll_path))
    return ELAN_ENGINE_ERROR;
  u32(MS * query_interface)(void **) = get_export("WbioQueryEngineInterface");
  void *iface = NULL;
  if (!query_interface)
    return fail("Finding WbioQueryEngineInterface", 0);
  u32 hr = query_interface(&iface);
  if (hr || !iface)
    return fail("WbioQueryEngineInterface", hr);

  // WINBIO_ENGINE_INTERFACE: methods follow a 32-byte version/type/size/GUID header.
  void **methods = (void **)((u8 *)iface + 32);
  attach = methods[0];
  detach = methods[1];
  accept_sample = methods[8];
  verify = methods[10];
  create_enrollment = methods[12];
  update_enrollment = methods[13];
  enrollment_status = methods[14];
  commit_enrollment = methods[17];

  for (int i = 0; i < 64; i++)
    sensor[i] = storage[i] = (void *)unsupported_callback;
  sensor[0x88 / 8] = (void *)sensor_control;
  storage[0x68 / 8] = (void *)add_record;
  storage[0x70 / 8] = (void *)delete_record;
  storage[0x78 / 8] = (void *)query_by_subject;
  storage[0x90 / 8] = (void *)first_record;
  storage[0x98 / 8] = (void *)next_record;
  storage[0xa0 / 8] = (void *)get_current_record;
  pipeline[4] = iface; // EngineInterface

  *(u32 *)(bir + 0x00) = 0x30;                          // HeaderBlock.Size
  *(u32 *)(bir + 0x04) = 0x18;                          // HeaderBlock.Offset
  *(u32 *)(bir + 0x08) = 0x38 + ELAN_ENGINE_FRAME_SIZE; // StandardDataBlock.Size
  *(u32 *)(bir + 0x0c) = 0x48;                          // StandardDataBlock.Offset
  *(u16 *)(bir + 0x18 + 0x28) = 0x001b;                 // BiometricDataFormat: ANSI 381 owner
  *(u16 *)(bir + 0x18 + 0x2a) = 0x0401;                 // BiometricDataFormat: ANSI 381 type
  // ELAN reads the frame size from the ANSI 381 header's image resolution fields
  // (+0x1c/+0x1e), not the record's line lengths that FocalTech uses.
  *(u16 *)(bir + 0x48 + 0x1c) = ELAN_ENGINE_WIDTH;
  *(u16 *)(bir + 0x48 + 0x1e) = ELAN_ENGINE_HEIGHT;
  return 0;
}

int elan_engine_open(const char *dll_path) {
  static int loaded;
  if (!loaded) {
    if (load(dll_path))
      return ELAN_ENGINE_ERROR;
    loaded = 1;
  }
  set_gs();
  void *iface = pipeline[4];
  memset(pipeline, 0, sizeof pipeline);
  pipeline[1] = (void *)-1; // EngineHandle
  pipeline[3] = sensor;     // SensorInterface
  pipeline[4] = iface;      // EngineInterface
  pipeline[5] = storage;    // StorageInterface
  template_size = 0;
  u32 hr = attach(pipeline);
  return hr ? fail("Attach", hr) : 0;
}

void elan_engine_close(void) {
  set_gs();
  u32 hr = detach(pipeline);
  if (hr)
    fail("Detach", hr);
}

// Hands a frame to AcceptSampleData: 0, ELAN_ENGINE_BAD or ELAN_ENGINE_ERROR.
static int accept(const uint8_t *frame, u8 purpose) {
  memcpy(bir + 0x48 + 0x38, frame, ELAN_ENGINE_FRAME_SIZE);
  u32 reject = 0;
  u32 hr = accept_sample(pipeline, bir, sizeof bir, purpose, &reject);
  if (hr == WINBIO_E_BAD_CAPTURE) {
    fprintf(stderr, "ELAN engine: bad capture (reject detail %u)\n", reject);
    return ELAN_ENGINE_BAD;
  }
  return hr ? fail("AcceptSampleData", hr) : 0;
}

int elan_engine_enroll_begin(void) {
  set_gs();
  template_size = 0; // nothing enrolled for the engine to compare against
  u32 hr = create_enrollment(pipeline);
  return hr ? fail("CreateEnrollment", hr) : 0;
}

int elan_engine_enroll_add(const uint8_t *frame) {
  set_gs();
  int r = accept(frame, WINBIO_PURPOSE_ENROLL);
  if (r)
    return r;
  u32 reject = 0;
  u32 hr = update_enrollment(pipeline, &reject);
  if (hr && hr != WINBIO_I_MORE_DATA)
    return fail("UpdateEnrollment", hr);
  hr = enrollment_status(pipeline, &reject);
  if (hr == WINBIO_I_MORE_DATA)
    return ELAN_ENGINE_MORE;
  return hr ? fail("GetEnrollmentStatus", hr) : ELAN_ENGINE_DONE;
}

int elan_engine_enroll_commit(uint8_t **tmpl, size_t *len) {
  set_gs();
  template_size = 0;
  u32 hr = commit_enrollment(pipeline, identity, SUBFACTOR, NULL, 0);
  if (hr || !template_size)
    return fail("CommitEnrollment", hr);
  *tmpl = malloc(template_size);
  if (!*tmpl)
    return ELAN_ENGINE_ERROR;
  memcpy(*tmpl, template_data, template_size);
  *len = template_size;
  return 0;
}

int elan_engine_accept(const uint8_t *frame) {
  set_gs();
  return accept(frame, WINBIO_PURPOSE_VERIFY);
}

int elan_engine_verify(const uint8_t *tmpl, size_t len) {
  if (!len || len > sizeof template_data) {
    fprintf(stderr, "ELAN engine: invalid template size %zu\n", len);
    return ELAN_ENGINE_ERROR;
  }
  set_gs();
  // Load the saved template every time, so that the engine's template
  // adaptation cannot train on the frames being verified.
  memcpy(template_data, tmpl, len);
  template_size = len;
  u8 match = 0;
  void *payload = NULL, *hash = NULL;
  u64 payload_size = 0, hash_size = 0;
  u32 reject = 0;
  u32 hr = verify(pipeline, identity, SUBFACTOR, &match, &payload, &payload_size, &hash,
                  &hash_size, &reject);
  if (hr == WINBIO_E_BAD_CAPTURE)
    return ELAN_ENGINE_BAD;
  if (hr && hr != WINBIO_E_NO_MATCH)
    return fail("VerifyFeatureSet", hr);
  return !hr && match;
}
