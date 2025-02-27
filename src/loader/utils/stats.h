#pragma once

#include <xdp/libxdp.h>

#include <common/all.h>

#include <loader/utils/cmdline.h>
#include <loader/utils/config.h>
#include <loader/utils/helpers.h>

#include <time.h>

int CalculateStats(int map_stats, int cpus, int per_second);