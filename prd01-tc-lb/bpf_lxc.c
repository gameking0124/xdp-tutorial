
#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <ep_config.h>
#include <node_config.h>
#include <bpf/verifier.h>
#include <linux/icmpv6.h>
#define EVENT_SOURCE LXC_ID


static __always_inline int handle_ipv4_from_lxc(struct __ctx_buff *ctx,
						__u32 *dstID)
{
    return CTX_ACT_OK;
}

__section("from-container")
int handle_xgress(struct __ctx_buff *ctx)
{
    __u32 dstID = 0;
	return handle_ipv4_from_lxc(ctx, &dstID);
}

__section("to-container")
int handle_xgress_drop(struct __ctx_buff *ctx)
{
    return CTX_ACT_DROP;
}

char _license[] __section("license") = "GPL";
