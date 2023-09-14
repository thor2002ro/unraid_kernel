// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Dummy prog to test TC-BPF API */

SEC("tc")
int cls(struct __sk_buff *skb)
{
	return 0;
}

/* Prog to verify tc-bpf without cap_sys_admin and cap_perfmon is rejected as
 * required to prevent Spectre v1 using CPU multiplication port contention
 * side-channel. This is not a full exploit but rather a PoC for x86_64. With
 * extensions to the verifier's mitigations this may become obsolete.
 *
 * This should compile to the following bytecode if the kernel would allow
 * unprivileged packet pointer accesses:
 *

0000000000000000 <pkt_ptr>:
       0:	b4 00 00 00 00 00 00 00	w0 = 0
       1:	61 12 50 00 00 00 00 00	r2 = *(u32 *)(r1 + 80)
       2:	61 11 4c 00 00 00 00 00	r1 = *(u32 *)(r1 + 76)
       3:	bf 13 00 00 00 00 00 00	r3 = r1
       4:	07 03 00 00 22 00 00 00	r3 += 34
       5:	bd 23 07 00 00 00 00 00	if r3 <= r2 goto +7 <LBB1_3>
       6:	71 10 0e 00 00 00 00 00	r0 = *(u8 *)(r1 + 14)
       7:	64 00 00 00 18 00 00 00	w0 <<= 24
       8:	c4 00 00 00 18 00 00 00	w0 s>>= 24
       9:	bc 01 00 00 00 00 00 00	w1 = w0
      10:	54 01 00 00 01 00 00 00	w1 &= 1
      11:	16 01 01 00 00 00 00 00	if w1 == 0 goto +1 <LBB1_3>
      12:	24 00 00 00 61 00 00 00	w0 *= 97

0000000000000068 <LBB1_3>:
      13:	95 00 00 00 00 00 00 00	exit

 *
 * Which should in turn translate to this x86_64 assembly with !allow_ptr_leaks
 * and !bypass_spec_v1:
 *

int pkt_ptr(struct __sk_buff * skb):
bpf_prog_7c3834bad32f2b0f_pkt_ptr:
; int pkt_ptr(struct __sk_buff *skb)
   0:   endbr64
   4:   nopl   0x0(%rax,%rax,1)
   9:   xchg   %ax,%ax
   b:   push   %rbp
   c:   mov    %rsp,%rbp
   f:   endbr64
  13:   xor    %eax,%eax
; if ((long)(iph + 1) > (long)skb->data_end)
  15:   mov    0x50(%rdi),%rsi
; struct iphdr *iph = (void *)(long)skb->data + sizeof(struct ethhdr);
  19:   mov    0xc8(%rdi),%rdi
; if ((long)(iph + 1) > (long)skb->data_end)
  20:   mov    %rdi,%rdx
  23:   add    $0x22,%rdx
; if ((long)(iph + 1) > (long)skb->data_end)
  27:   cmp    %rsi,%rdx
  2a:   ja     0x0000000000000043
; char secret = *((char *) iph);
  2c:   movzbq 0xe(%rdi),%rax
  31:   shl    $0x18,%eax
  34:   sar    $0x18,%eax
; if (secret & 1) {
  37:   mov    %eax,%edi
  39:   and    $0x1,%edi
; if (secret & 1) {
  3c:   test   %edi,%edi
  3e:   je     0x0000000000000043
  40:   imul   $0x61,%eax,%eax
; }
  43:   leaveq
  44:   retq

 *
 */
SEC("tcx/ingress")
int pkt_ptr(struct __sk_buff *skb)
{
	struct iphdr *iph = (void *)(long)skb->data + sizeof(struct ethhdr);

	/* Branch to be speculatively bypassed. */
	if ((long)(iph + 1) > (long)skb->data_end)
		return 0;

	/* Speculative access to be prevented. */
	char secret = *((char *) iph);

	/* Leak the first bit of the secret value that lies behind data_end to a
	 * SMP silbling thread that also executes imul instructions. If the bit
	 * is 1, the silbling will experience a slowdown. */
	long long x = secret;
	if (secret & 1) {
		x *= 97;
	}

	/* To prevent optimization. */
	return x;
}
