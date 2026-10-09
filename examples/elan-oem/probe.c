// SPDX-License-Identifier: LGPL-2.1-or-later
// Runs ELAN's WinBio engine adapter on saved 96x96 grayscale frames through the
// elan_oem driver's engine glue. There is no USB access.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elan_oem_engine.h"

static int read_file(const char *path, uint8_t *buf, size_t size, size_t *read_size) {
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

  static uint8_t saved_template[1024 * 1024];
  size_t saved_size = 0;
  if (verifying &&
      (read_file(argv[3], saved_template, sizeof saved_template, &saved_size) || !saved_size))
    return 2;

  if (elan_engine_open(argv[1]))
    return 2;
  if (!strcmp(mode, "init")) {
    elan_engine_close();
    printf("Engine initialized\n");
    return 0;
  }
  if (!verifying && elan_engine_enroll_begin())
    return 2;

  uint8_t *template = NULL;
  size_t template_size = 0;
  int matches = 0, attempts = 0;
  for (int arg = 4; arg < argc; arg++) {
    const char *frame = argv[arg];
    uint8_t pixels[ELAN_ENGINE_FRAME_SIZE];
    size_t size;
    if (read_file(frame, pixels, sizeof pixels, &size))
      return 2;
    if (size != sizeof pixels) {
      fprintf(stderr, "%s: expected %d bytes, got %zu\n", frame, ELAN_ENGINE_FRAME_SIZE, size);
      return 2;
    }

    if (verifying) {
      int r = elan_engine_accept(pixels);
      if (!r)
        r = elan_engine_verify(saved_template, saved_size);
      if (r < 0)
        return 2;
      attempts++;
      matches += r == 1;
      printf("%s: %s\n", frame,
             r == ELAN_ENGINE_BAD ? "bad capture" : r == 1 ? "match" : "no match");
      continue;
    }

    int r = elan_engine_enroll_add(pixels);
    if (r < 0)
      return 2;
    if (r == ELAN_ENGINE_BAD) {
      printf("%s: bad capture\n", frame);
      continue;
    }
    if (r == ELAN_ENGINE_MORE) {
      printf("%s: accepted\n", frame);
      continue;
    }
    if (elan_engine_enroll_commit(&template, &template_size))
      return 2;
    int fd = open(argv[3], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
      perror(argv[3]);
      return 2;
    }
    if (write(fd, template, template_size) != (ssize_t)template_size || close(fd)) {
      perror(argv[3]);
      return 2;
    }
    printf("%s: enrollment complete, %zu-byte template saved to %s\n", frame, template_size,
           argv[3]);
    break;
  }

  elan_engine_close();
  if (verifying) {
    printf("Matched %d/%d frames\n", matches, attempts);
    return matches == attempts ? 0 : 1;
  }
  if (!template) {
    printf("Enrollment incomplete: more touches needed\n");
    return 1;
  }
  free(template);
  return 0;
}
