#include <bpf.h>
#include <libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "libiu.h"

#define BPF_SYSFS_ROOT "/sys/fs/bpf"

#define EXE "./target/x86_64-unknown-linux-gnu/release/mp4-sample"

static int nr_cpus = 0;

struct bpf_progs_desc
{
  char name[256];
  enum bpf_prog_type type;
  unsigned char pin;
  int map_prog_idx;
  struct bpf_program *prog;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
  if (level == LIBBPF_DEBUG || level == LIBBPF_INFO)
  {
    return vfprintf(stderr, format, args);
  }
  return 0;
}

int main(int argc, char *argv[])
{
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  int base_fd, rx_prog_fd, tx_prog_fd, xdp_main_prog_fd;
  struct bpf_object_load_attr load_attr;
  struct bpf_program *rx_prog, *tx_prog;
  struct bpf_object *obj;
  int map_progs_xdp_fd;
  char filename[PATH_MAX];
  int err, prog_count;
  __u32 xdp_flags = 0;
  __u16 blocked_port;
  int interface_idx;
  int ret = 0;
  __u8 udp_blocked;
  __u8 tcp_blocked;

  if (argc != 2 && argc != 4)
  {
    fprintf(stderr, "Usage: %s <interface index>\n", argv[0]);
    fprintf(stderr, "Usage: %s add_rule <port> <protocol>\n", argv[0]);
    return 1;
  }

  if (argc == 2)
  {
    libbpf_set_print(libbpf_print_fn);
    iu_set_debug(1); // enable debug info

    interface_idx = atoi(argv[1]);
    nr_cpus = libbpf_num_possible_cpus();

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
      perror("setrlimit failed");
      return 1;
    }

    obj = iu_object__open(EXE);
    if (!obj)
    {
      fprintf(stderr, "Object could not be opened\n");
      exit(1);
    }

    map_progs_xdp_fd = bpf_object__find_map_fd_by_name(obj, "map_hash");
    if (map_progs_xdp_fd < 0)
    {
      fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
      return 1;
    }

    rx_prog = bpf_object__find_program_by_name(obj, "xdp_rx_filter");
    if (!rx_prog)
    {
      fprintf(stderr, "start not found\n");
      exit(1);
    }

    xdp_main_prog_fd = bpf_program__fd(rx_prog);
    if (xdp_main_prog_fd < 0)
    {
      fprintf(stderr, "Error: bpf_program__fd failed\n");
      return 1;
    }

    // xdp_flags |= XDP_FLAGS_DRV_MODE;
    xdp_flags |= XDP_FLAGS_SKB_MODE;
    if (bpf_set_link_xdp_fd(interface_idx, xdp_main_prog_fd, xdp_flags) <
        0)
    {
      fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n",
              interface_idx);
      return 1;
    }
    else
    {
      printf("Main BPF program attached to XDP on interface %d\n",
             interface_idx);
    }
    bpf_obj_pin(map_progs_xdp_fd, "/sys/fs/bpf/entry");
  }
  else
  {
    blocked_port = (__u8)atoi(argv[2]);
    udp_blocked = strcmp(argv[3], "udp") == 0 ? 1 : 0;
    tcp_blocked = strcmp(argv[3], "tcp") == 0 ? 1 : 0;
    int fd = bpf_obj_get("/sys/fs/bpf/entry");
    printf("Adding rule for port %d, tcp blocked is %hhu\n", blocked_port, tcp_blocked);
    err = bpf_map_update_elem(fd, &blocked_port, &tcp_blocked, BPF_ANY);
    if (err)
    {
      perror("bpf_map_update_elem failed");
      return 1;
    }
  }

  return ret;
}
