#ifndef SPEED_LIMIT_H

#include <math.h>

#include "config.h"

#define DY (SPEED_LIMIT_MAX - SPEED_LIMIT_MIN)
#define DX (SPEED_LIMIT_DROP_STOP - SPEED_LIMIT_DROP_START)
//stretch y       stretch x     shift x      shift y
// 45 *      cos((M_PI / 70) * ((x) - 30)) + 75
#ifndef DEBUG_EBPF_ONLY
#define SPEED_LIMIT_DROP_FUNC(x)                                               \
	(DY / 2.0) * cos((M_PI / DX) * ((x)-SPEED_LIMIT_DROP_START)) +             \
			(SPEED_LIMIT_MIN + DY / 2.0)
#else
#define SPEED_LIMIT_DROP_FUNC(x)                                               \
	(DY / 2) * cos((3 / DX) * ((x)-SPEED_LIMIT_DROP_START)) +                  \
			(SPEED_LIMIT_MIN + DY / 2)
#endif

#define SPEED_LIMIT_H
#endif /* ifndef SPEED_LIMIT_H */
