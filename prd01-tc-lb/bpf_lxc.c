
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

char _license[] SEC("license") = "GPL";
