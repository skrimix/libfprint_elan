// SPDX-License-Identifier: LGPL-2.1-or-later
// Runs ELAN's WinBio engine adapter on saved 96x96 grayscale frames. The sensor
// and storage adapters are minimal in-process stubs; there is no USB access.
#include "pe-loader.c"

#define WIDTH 96
#define HEIGHT 96
#define FRAME_SIZE (WIDTH * HEIGHT)
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
  ((u32 *)receive)[0] = WIDTH;
  ((u32 *)receive)[1] = HEIGHT;
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

static int fail(const char *what, u32 hr) {
  fprintf(stderr, "%s failed: %#x\n", what, hr);
  return 2;
}

static int read_file(const char *path, u8 *buf, u64 size, u64 *read_size) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    perror(path);
    return -1;
  }
  *read_size = fread(buf, 1, size, fp);
  int ok = !ferror(fp) && fgetc(fp) == EOF;
  fclose(fp);
  if (!ok)
    fprintf(stderr, "%s: read error or file too large\n", path);
  return ok ? 0 : -1;
}

int main(int argc, char **argv) {
  const char *mode = argc > 2 ? argv[2] : "";
  int verifying = !strcmp(mode, "verify");
  if (!(!strcmp(mode, "init") && argc == 3) &&
      !((verifying || !strcmp(mode, "enroll")) && argc > 4)) {
    fprintf(stderr,
            "Usage: %s EngineAdapter.dll init\n"
            "       %s EngineAdapter.dll enroll TEMPLATE FRAME.raw ...\n"
            "       %s EngineAdapter.dll verify TEMPLATE FRAME.raw ...\n",
            argv[0], argv[0], argv[0]);
    return 2;
  }
  setvbuf(stdout, NULL, _IOLBF, 0);

  static u8 saved_template[sizeof template_data];
  u64 saved_size = 0;
  if (verifying &&
      (read_file(argv[3], saved_template, sizeof saved_template, &saved_size) || !saved_size))
    return 2;

  if (load_pe(argv[1]))
    return 2;
  u32(MS * query_interface)(void **) = get_export("WbioQueryEngineInterface");
  void *iface = NULL;
  if (!query_interface)
    return fail("Finding WbioQueryEngineInterface", 0);
  u32 hr = query_interface(&iface);
  if (hr || !iface)
    return fail("WbioQueryEngineInterface", hr);

  // WINBIO_ENGINE_INTERFACE: methods follow a 32-byte version/type/size/GUID header.
  void **methods = (void **)((u8 *)iface + 32);
  u32(MS * attach)(void *) = methods[0];
  u32(MS * detach)(void *) = methods[1];
  u32(MS * accept_sample)(void *, void *, u64, u8, u32 *) = methods[8];
  u32(MS * verify)(void *, void *, u8, u8 *, void **, u64 *, void **, u64 *, u32 *) = methods[10];
  u32(MS * create_enrollment)(void *) = methods[12];
  u32(MS * update_enrollment)(void *, u32 *) = methods[13];
  u32(MS * enrollment_status)(void *, u32 *) = methods[14];
  u32(MS * commit_enrollment)(void *, void *, u8, void *, u64) = methods[17];

  // Adapter interface tables, indexed by byte offset of each method.
  void *sensor[64], *storage[64];
  for (int i = 0; i < 64; i++)
    sensor[i] = storage[i] = (void *)unsupported_callback;
  sensor[0x88 / 8] = (void *)sensor_control;
  storage[0x68 / 8] = (void *)add_record;
  storage[0x70 / 8] = (void *)delete_record;
  storage[0x78 / 8] = (void *)query_by_subject;
  storage[0x90 / 8] = (void *)first_record;
  storage[0x98 / 8] = (void *)next_record;
  storage[0xa0 / 8] = (void *)get_current_record;

  // WINBIO_PIPELINE; the engine stores its context in it during attach.
  void *pipeline[128] = {0};
  pipeline[1] = (void *)-1; // EngineHandle
  pipeline[3] = sensor;     // SensorInterface
  pipeline[4] = iface;      // EngineInterface
  pipeline[5] = storage;    // StorageInterface

  if ((hr = attach(pipeline)))
    return fail("Attach", hr);
  if (!strcmp(mode, "init")) {
    if ((hr = detach(pipeline)))
      return fail("Detach", hr);
    printf("Engine initialized\n");
    return 0;
  }
  if (!verifying && (hr = create_enrollment(pipeline)))
    return fail("CreateEnrollment", hr);

  // WINBIO_BIR: a WINBIO_BIR_HEADER followed by an ANSI 381 standard data block.
  static u8 bir[0x80 + FRAME_SIZE];
  *(u32 *)(bir + 0x00) = 0x30;              // HeaderBlock.Size
  *(u32 *)(bir + 0x04) = 0x18;              // HeaderBlock.Offset
  *(u32 *)(bir + 0x08) = 0x38 + FRAME_SIZE; // StandardDataBlock.Size
  *(u32 *)(bir + 0x0c) = 0x48;              // StandardDataBlock.Offset
  *(u16 *)(bir + 0x18 + 0x28) = 0x001b;     // BiometricDataFormat: ANSI 381 owner
  *(u16 *)(bir + 0x18 + 0x2a) = 0x0401;     // BiometricDataFormat: ANSI 381 type
  // ELAN reads the frame size from the ANSI 381 header's image resolution fields
  // (+0x1c/+0x1e), not the record's line lengths that FocalTech uses.
  *(u16 *)(bir + 0x48 + 0x1c) = WIDTH;
  *(u16 *)(bir + 0x48 + 0x1e) = HEIGHT;
  u8 *pixels = bir + 0x48 + 0x38;

  int matches = 0, attempts = 0;
  for (int arg = 4; arg < argc; arg++) {
    const char *frame = argv[arg];
    u64 size;
    if (read_file(frame, pixels, FRAME_SIZE, &size))
      return 2;
    if (size != FRAME_SIZE) {
      fprintf(stderr, "%s: expected %d bytes, got %lu\n", frame, FRAME_SIZE, size);
      return 2;
    }
    u32 reject = 0;
    hr = accept_sample(pipeline, bir, sizeof bir,
                       verifying ? WINBIO_PURPOSE_VERIFY : WINBIO_PURPOSE_ENROLL, &reject);
    if (hr == WINBIO_E_BAD_CAPTURE) {
      printf("%s: bad capture (reject detail %u)\n", frame, reject);
      attempts += verifying;
      continue;
    }
    if (hr)
      return fail("AcceptSampleData", hr);

    if (verifying) {
      // Verify against the saved enrollment every time, so that template
      // adaptation cannot train on the frames being evaluated.
      memcpy(template_data, saved_template, saved_size);
      template_size = saved_size;
      u8 match = 0;
      void *payload = NULL, *hash = NULL;
      u64 payload_size = 0, hash_size = 0;
      hr = verify(pipeline, identity, SUBFACTOR, &match, &payload, &payload_size, &hash,
                  &hash_size, &reject);
      if (hr && hr != WINBIO_E_NO_MATCH && hr != WINBIO_E_BAD_CAPTURE)
        return fail("VerifyFeatureSet", hr);
      attempts++;
      matches += !hr && match;
      printf("%s: %s\n", frame, !hr && match ? "match" : "no match");
      continue;
    }

    hr = update_enrollment(pipeline, &reject);
    if (hr && hr != WINBIO_I_MORE_DATA)
      return fail("UpdateEnrollment", hr);
    hr = enrollment_status(pipeline, &reject);
    if (hr == WINBIO_I_MORE_DATA) {
      printf("%s: accepted\n", frame);
      continue;
    }
    if (hr)
      return fail("GetEnrollmentStatus", hr);
    if ((hr = commit_enrollment(pipeline, identity, SUBFACTOR, NULL, 0)) || !template_size)
      return fail("CommitEnrollment", hr);
    int fd = open(argv[3], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
      perror(argv[3]);
      return 2;
    }
    if (write(fd, template_data, template_size) != (ssize_t)template_size || close(fd)) {
      perror(argv[3]);
      return 2;
    }
    printf("%s: enrollment complete, %lu-byte template saved to %s\n", frame, template_size,
           argv[3]);
    break;
  }

  if ((hr = detach(pipeline)))
    return fail("Detach", hr);
  if (verifying) {
    printf("Matched %d/%d frames\n", matches, attempts);
    return matches == attempts ? 0 : 1;
  }
  if (!template_size) {
    printf("Enrollment incomplete: more touches needed\n");
    return 1;
  }
  return 0;
}
