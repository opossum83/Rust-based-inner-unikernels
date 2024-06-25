#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

extern crate inner_unikernel_rt;

use core::ffi::c_void;
use core::mem::{size_of, swap};
use core::num::Wrapping;
use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::linux::bpf::BPF_MAP_TYPE_HASH;
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::utils::*;
use inner_unikernel_rt::xdp::*;
use inner_unikernel_rt::FieldTransmute;
use inner_unikernel_rt::MAP_DEF;

MAP_DEF!(map_hash, u16, u8, BPF_MAP_TYPE_HASH, 1024, 0);

fn xdp_rx_filter_fn(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let ip_header = obj.ip_header(ctx);

    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_TCP => {
            let tcp_header = obj.tcp_header(ctx);
            let port = u16::from_be(tcp_header.dest);

            match obj.bpf_map_lookup_elem(&map_hash, &port) {
                None => {
                    return Ok(XDP_PASS as i32);
                }
                Some(val) => {
                    if ((*val) as u8 == 1) {
                        return Ok(XDP_DROP as i32);
                    } else {
                        return Ok(XDP_PASS as i32);
                    }
                }
            }
        }
        IPPROTO_UDP => {
            return Ok(XDP_DROP as i32);
        }
        _ => {}
    };

    Ok(XDP_PASS as i32)
}

#[entry_link(inner_unikernel/xdp)]
static PROG1: xdp = xdp::new(xdp_rx_filter_fn, "xdp_rx_filter", BPF_PROG_TYPE_XDP as u64);
