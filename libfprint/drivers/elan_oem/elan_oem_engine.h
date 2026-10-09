// SPDX-License-Identifier: LGPL-2.1-or-later
// ELAN's WinBio engine adapter (EngineAdapter.dll 1.1.0.2111), loaded in-process.
#pragma once

#include <stddef.h>
#include <stdint.h>

#define ELAN_ENGINE_WIDTH 96
#define ELAN_ENGINE_HEIGHT 96
#define ELAN_ENGINE_FRAME_SIZE (ELAN_ENGINE_WIDTH * ELAN_ENGINE_HEIGHT)

// Results besides 0/1; negative values are engine failures.
#define ELAN_ENGINE_MORE 2 // enrollment needs more touches
#define ELAN_ENGINE_DONE 3 // enrollment complete, commit it
#define ELAN_ENGINE_BAD 4  // the engine rejected the frame
#define ELAN_ENGINE_ERROR -1

// Loads the DLL on first use (it stays mapped for the life of the process) and
// attaches a pipeline. Returns 0 or ELAN_ENGINE_ERROR.
int elan_engine_open(const char *dll_path);
void elan_engine_close(void);

int elan_engine_enroll_begin(void);
// Feeds an 8-bit 96x96 frame: ELAN_ENGINE_MORE, _DONE, _BAD or _ERROR.
int elan_engine_enroll_add(const uint8_t *frame);
// On success returns 0 and a malloc'd template the caller frees.
int elan_engine_enroll_commit(uint8_t **tmpl, size_t *len);

// Extracts features from a frame for elan_engine_verify: 0, ELAN_ENGINE_BAD
// or _ERROR.
int elan_engine_accept(const uint8_t *frame);
// Compares the last accepted frame with a committed template: 1 match,
// 0 no match, ELAN_ENGINE_BAD or _ERROR. The frame stays accepted, so it can be
// compared with several templates. The engine's template adaptation is discarded.
int elan_engine_verify(const uint8_t *tmpl, size_t len);
