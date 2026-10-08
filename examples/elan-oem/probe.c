// SPDX-License-Identifier: LGPL-2.1-or-later
// Standalone ELAN WinBio engine bring-up; no USB access or system installation.
#include "pe-loader.c"
#include <sys/stat.h>

static u32 MS sensor_control(void *pipeline, u32 code, void *send, u64 send_size, void *receive,
                             u64 receive_size, u64 *received, u32 *status) {
  fprintf(stderr, "Sensor control %#x, input=%lu, output=%lu\n", code, send_size, receive_size);
  if (code != 0x442080 || receive_size != 8)
    abort();
  // GET_SENSOR_DIMENSIONS, confirmed against WbfUsbDriver.dll and the reader.
  ((u32 *)receive)[0] = 96;
  ((u32 *)receive)[1] = 96;
  *received = 8;
  *status = 0;
  return 0;
}

static u32 MS unsupported_callback(void) {
  fprintf(stderr, "Unimplemented WinBio callback\n");
  abort();
}

static u8 template_data[1024 * 1024], identity[76];
static u64 template_size;

static u32 MS add_record(void *pipeline, u8 *record) {
  u64 size = *(u64 *)(record + 0x28);
  if (!size || size > sizeof template_data)
    abort();
  memcpy(template_data, *(void **)(record + 0x20), size);
  template_size = size;
  return 0;
}

static u32 MS query_record(void *pipeline, void *id, u8 finger) {
  return template_size && finger == 1 && !memcmp(id, identity, sizeof identity) ? 0 : 0x8009801f;
}

static u32 MS first_record(void *pipeline) { return template_size ? 0 : 0x8009801f; }
static u32 MS next_record(void *pipeline) { return 0x80098020; }
static u32 MS delete_record(void *pipeline, void *id, u8 finger) {
  template_size = 0;
  return 0;
}

static u32 MS get_record(void *pipeline, u8 *record) {
  memset(record, 0, 64);
  *(void **)record = identity;
  record[8] = 1;
  *(void **)(record + 0x20) = template_data;
  *(u64 *)(record + 0x28) = template_size;
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3 || (strcmp(argv[2], "init") &&
                   ((strcmp(argv[2], "enroll") && strcmp(argv[2], "verify")) || argc < 5))) {
    fprintf(stderr,
            "Usage: %s EngineAdapter.dll init\n"
            "       %s EngineAdapter.dll enroll TEMPLATE FRAME.raw ...\n"
            "       %s EngineAdapter.dll verify TEMPLATE FRAME.raw ...\n",
            argv[0], argv[0], argv[0]);
    return 2;
  }
  int verifying = !strcmp(argv[2], "verify");
  u8 original_template[sizeof template_data];
  u64 original_size = 0;
  if (verifying) {
    FILE *fp = fopen(argv[3], "rb");
    if (!fp) {
      perror(argv[3]);
      return 2;
    }
    original_size = fread(original_template, 1, sizeof original_template, fp);
    if (!original_size || fgetc(fp) != EOF || ferror(fp)) {
      fprintf(stderr, "Invalid template size or read error\n");
      return 2;
    }
    fclose(fp);
  }
  g_dllpath = argv[1];
  register_shims();
  if (load_pe() != 0)
    return 2;
  u32(MS * query)(void **) = get_export("WbioQueryEngineInterface");
  if (!query)
    abort();
  void *iface = NULL;
  u32 hr = query(&iface);
  fprintf(stderr, "WbioQueryEngineInterface: %#x, interface=%p\n", hr, iface);
  if (hr || !iface)
    return 2;
  fprintf(stderr, "Interface version=%u, type=%u, size=%u\n", ((u32 *)iface)[0], ((u32 *)iface)[1],
          ((u32 *)iface)[2]);

  u64 pipeline[128] = {0}, sensor[64], storage[64];
  for (int i = 0; i < 64; i++) {
    sensor[i] = (u64)unsupported_callback;
    storage[i] = (u64)unsupported_callback;
  }
  sensor[0x88 / 8] = (u64)sensor_control;
  storage[0x68 / 8] = (u64)add_record;
  storage[0x70 / 8] = (u64)delete_record;
  storage[0x78 / 8] = (u64)query_record;
  storage[0x90 / 8] = (u64)first_record;
  storage[0x98 / 8] = (u64)next_record;
  storage[0xa0 / 8] = (u64)get_record;
  *(u32 *)identity = 3; // WINBIO_ID_TYPE_SID, single local test identity.
  *(u32 *)(identity + 4) = 8;
  identity[8] = 1;
  identity[9] = 0;
  identity[15] = 5;
  pipeline[1] = ~0ULL;
  pipeline[3] = (u64)sensor;
  pipeline[4] = (u64)iface;
  pipeline[5] = (u64)storage;
  void **methods = (void **)((u8 *)iface + 32);
  u32(MS * attach)(void *) = methods[0];
  u32(MS * detach)(void *) = methods[1];
  u32(MS * create)(void *) = methods[12];
  u32(MS * accept)(void *, void *, u64, u8, u32 *) = methods[8];
  u32(MS * update)(void *, u32 *) = methods[13];
  u32(MS * status)(void *, u32 *) = methods[14];
  u32(MS * commit)(void *, void *, u8, void *, u64) = methods[17];
  u32(MS * verify)(void *, void *, u8, u8 *, void **, u64 *, void **, u64 *, u32 *) = methods[10];
  hr = attach(pipeline);
  fprintf(stderr, "Attach: %#x\n", hr);
  if (hr)
    return 2;
  if (!strcmp(argv[2], "init")) {
    hr = detach(pipeline);
    printf("INIT %s\n", hr ? "FAILED" : "OK");
    return hr ? 2 : 0;
  }
  if (!verifying) {
    hr = create(pipeline);
    fprintf(stderr, "CreateEnrollment: %#x\n", hr);
    if (hr)
      return 2;
  }

  u8 bir[0x80 + 96 * 96] = {0};
  *(u32 *)(bir + 0) = 0x30;
  *(u32 *)(bir + 4) = 0x18;
  *(u32 *)(bir + 8) = 0x38 + 96 * 96;
  *(u32 *)(bir + 12) = 0x48;
  *(u16 *)(bir + 0x18 + 0x28) = 0x1b;
  *(u16 *)(bir + 0x18 + 0x2a) = 0x401;
  // This ELAN build reads dimensions at +0x1c/+0x1e, not FocalTech's +0x2c/+0x2e.
  *(u16 *)(bir + 0x48 + 0x1c) = 96;
  *(u16 *)(bir + 0x48 + 0x1e) = 96;
  int enrolled = 0, matches = 0, attempts = 0;
  for (int arg = 4; arg < argc; arg++) {
    FILE *fp = fopen(argv[arg], "rb");
    if (!fp) {
      perror(argv[arg]);
      return 2;
    }
    if (fread(bir + 0x80, 1, 96 * 96, fp) != 96 * 96 || fgetc(fp) != EOF) {
      fprintf(stderr, "Expected exactly 9216 image bytes\n");
      return 2;
    }
    fclose(fp);
    u32 reject = 0;
    hr = accept(pipeline, bir, sizeof bir, verifying ? 1 : 4, &reject);
    printf("SAMPLE %s accept=%#x reject=%u\n", argv[arg], hr, reject);
    fflush(stdout);
    if (hr == 0x80098008) {
      if (verifying)
        attempts++;
      continue;
    }
    if (hr)
      return 2;
    if (!verifying) {
      hr = update(pipeline, &reject);
      printf("UPDATE hr=%#x reject=%u\n", hr, reject);
      if (hr != 0 && hr != 0x90001)
        return 2;
      hr = status(pipeline, &reject);
      if (hr == 0) {
        hr = commit(pipeline, identity, 1, NULL, 0);
        printf("COMMIT hr=%#x template_size=%lu\n", hr, template_size);
        if (hr || !template_size)
          return 2;
        int fd = open(argv[3], O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) {
          perror(argv[3]);
          return 2;
        }
        if (write(fd, template_data, template_size) != (ssize_t)template_size || close(fd)) {
          perror("write template");
          return 2;
        }
        enrolled = 1;
        break;
      } else if (hr != 0x90001)
        return 2;
    } else {
      // Each test uses the saved enrollment: do not let template adaptation make
      // later verification samples part of the enrollment under evaluation.
      memcpy(template_data, original_template, original_size);
      template_size = original_size;
      u8 match = 0;
      void *payload = NULL, *hash = NULL;
      u64 payload_size = 0, hash_size = 0;
      hr = verify(pipeline, identity, 1, &match, &payload, &payload_size, &hash, &hash_size,
                  &reject);
      printf("VERIFY %s hr=%#x match=%u reject=%u\n", argv[arg], hr, match, reject);
      if (hr != 0 && hr != 0x80098005 && hr != 0x80098008)
        return 2;
      attempts++;
      if (!hr && match)
        matches++;
    }
    fflush(stdout);
  }
  hr = detach(pipeline);
  if (hr) {
    fprintf(stderr, "Detach failed: %#x\n", hr);
    return 2;
  }
  if (verifying) {
    printf("RESULT %d/%d matched\n", matches, attempts);
    return matches == attempts ? 0 : 1;
  }
  printf("ENROLL %s\n", enrolled ? "COMPLETE" : "NEEDS_MORE_TOUCHES");
  return enrolled ? 0 : 1;
}
