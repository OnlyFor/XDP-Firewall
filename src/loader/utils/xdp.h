#pragma once

#include <bpf.h>
#include <libbpf.h>
#include <xdp/libxdp.h>

#include  <common/all.h>

#include <loader/utils/cmdline.h>
#include <loader/utils/config.h>
#include <loader/utils/helpers.h>

#define XDP_OBJ_PATH "/etc/xdpfw/xdp_prog.o"

int FindMapFd(struct xdp_program *prog, const char *map_name);
struct xdp_program *LoadBpfObj(const char *file_name);
int AttachXdp(struct xdp_program *prog, int ifidx, u8 detach, cmdline_t *cmd);
void UpdateFilters(int filters_map, config__t *cfg);