
#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <ep_config.h>
#include <node_config.h>
#include <bpf/verifier.h>
#include <linux/icmpv6.h>
#define EVENT_SOURCE LXC_ID

#include "lib/tailcall.h"
#include "lib/common.h"
#include "lib/config.h"
#include "lib/maps.h"
#include "lib/arp.h"
#include "lib/edt.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/lxc.h"
#include "lib/nat46.h"
#include "lib/identity.h"
#include "lib/policy.h"
#include "lib/lb.h"
#include "lib/drop.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/csum.h"
#include "lib/encap.h"
#include "lib/eps.h"
#include "lib/nat.h"
#include "lib/fib.h"
#include "lib/nodeport.h"
#include "lib/policy_log.h"

static __always_inline int handle_ipv4_from_lxc(struct __ctx_buff *ctx,
						__u32 *dstID)
{
    return CTX_ACT_OK;
}

__section("from-container")
int handle_xgress(struct __ctx_buff *ctx)
{
    __u16 proto;
    __u32 dstID = 0;
    int ret = CTX_ACT_OK;
    bpf_clear_meta(ctx);

    if(!validate_ethertype(ctx,&proto)){
        ret = DROP_UNSUPPORTED_L2;
        goto out;
    }
    switch(proto){
	case bpf_htons(ETH_P_IP):
		ret = handle_ipv4_from_lxc(ctx, &dstID);
		break;
	case bpf_htons(ETH_P_IPV6):
	    // do something
	default:
		ret = DROP_UNKNOWN_L3;
    }
out:
    return ret;
}

__section("to-container")
int handle_xgress_drop(struct __ctx_buff *ctx)
{
    return CTX_ACT_DROP;
}

char _license[] __section("license") = "GPL";
