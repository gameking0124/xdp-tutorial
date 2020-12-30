
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("from-container")
int handle_xgress(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
