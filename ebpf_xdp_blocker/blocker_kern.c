#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf/bpf_helpers.h"
#include "blocker_common.h"
#include <linux/in.h>

struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct port_rule),
    .max_entries = 65536,
};

SEC("xdp_port_blocker")
int xdp_filter_by_port(struct xdp_md *ctx)
{
  // convert the packet to a series of netowkr headers
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Check if the packet is large enough for Ethernet + IP + TCP headers
  struct ethhdr *eth = data;
  struct iphdr *ip = data + sizeof(*eth);
  struct tcphdr *tcp = (void *)ip + sizeof(*ip);
  if ((void *)tcp + sizeof(*tcp) > data_end)
  {
    return XDP_PASS;
  }
  

  // filter UDP packets
  if (ip->protocol == IPPROTO_UDP)
  {
    return XDP_DROP;
  }

  // You may need to get the filter rules from the map
  u32 d_port = ntohs(tcp->dest);
  struct port_rule *blocked_rule = bpf_map_lookup_elem(&port_map, &d_port);
  if (blocked_rule != NULL && blocked_rule->tcp_action == 1) 
  {
    bpf_printk("found packet dropped!\n");
    return XDP_DROP;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
