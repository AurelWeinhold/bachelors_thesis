#ifndef CONFIG_H

#define DEBUG 0
//#define DEBUG_USERSPACE_ONLY
//#define DEBUG_EBPF_ONLY

// how long should poll wait in seconds until timeout to recalculate the speed
// limit
#define POLL_WAIT_S            1

#define SPEED_LIMIT_DROP_START 30
#define SPEED_LIMIT_DROP_STOP  100
#define SPEED_LIMIT_MAX        120
#define SPEED_LIMIT_MIN        30

#define CONFIG_H
#endif /* ifndef CONFIG_H */
