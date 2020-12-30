
#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <ep_config.h>
#include <node_config.h>
#include <bpf/verifier.h>
#include <linux/icmpv6.h>
#define EVENT_SOURCE LXC_ID

__section("from-container")
int handle_xgress(struct __ctx_buff *ctx)
{
    return CTX_ACT_OK;
}

__section("to-container")
int handle_xgress_drop(struct __ctx_buff *ctx)
{
    return CTX_ACT_DROP;
}

char _license[] __section("license") = "GPL";
