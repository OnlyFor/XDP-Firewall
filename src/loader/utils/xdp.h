#pragma once

#include <xdp/libxdp.h>

#include  <common/all.h>

#include <loader/utils/config.h>
#include <loader/utils/helpers.h>

#define XDP_OBJ_PATH "/etc/xdpfw/xdp_prog.o"
#define XDP_MAP_PIN_DIR "/sys/fs/bpf/xdpfw"

int FindMapFd(struct xdp_program *prog, const char *map_name);
void SetLibBPFLogMode(int silent);

struct xdp_program *LoadBpfObj(const char *file_name);
struct bpf_object* GetBpfObj(struct xdp_program* prog);

int AttachXdp(struct xdp_program *prog, char** mode, int ifidx, int detach, int force_skb, int force_offload);

int DeleteFilter(int map_filters, u32 idx);
void DeleteFilters(int map_filters);

int UpdateFilter(int map_filters, filter_t* filter, int idx);
void UpdateFilters(int map_filters, config__t *cfg);

int PinBpfMap(struct bpf_object* obj, const char* pin_dir, const char* map_name);
int UnpinBpfMap(struct bpf_object* obj, const char* pin_dir, const char* map_name);
int GetMapPinFd(const char* pin_dir, const char* map_name);

int DeleteBlock(int map_block, u32 ip);
int AddBlock(int map_block, u32 ip, u64 expires);

int DeleteBlock6(int map_block6, u128 ip);
int AddBlock6(int map_block6, u128 ip, u64 expires);

int DeleteRangeDrop(int map_range_drop, u32 net, u8 cidr);
int AddRangeDrop(int map_range_drop, u32 net, u8 cidr);
void UpdateRangeDrops(int map_range_drop, config__t* cfg);