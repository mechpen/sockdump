#!/usr/bin/python
import math
import resource
from bcc import BPF
import ctypes as ct

# FIXME: sock path is relative

bpf_text = '''
#include <linux/sched.h>
#include <linux/net.h>
#include <uapi/linux/un.h>
#include <net/af_unix.h>

#define SS_MAX_SEG_SIZE     __SS_MAX_SEG_SIZE__
#define SS_MAX_NR_SEGS      __SS_MAX_NR_SEGS__

#define SS_PACKET_F_ERR     1

struct packet {
    u32 pid;
    u32 len;
    u32 flags;
    char comm[TASK_COMM_LEN];
    char data[SS_MAX_SEG_SIZE];
};

BPF_ARRAY(packet_array, struct packet, 1);
BPF_PERF_OUTPUT(events);

int probe_unix_stream_sendmsg(struct pt_regs *ctx,
                              struct socket *sock,
                              struct msghdr *msg,
                              size_t len)
{
    struct packet *packet;
    struct unix_address *addr;
    char *path, *buf;
    unsigned int n, match = 0;
    struct iov_iter *iter;
    const struct kvec *iov;

    addr = ((struct unix_sock *)sock->sk)->addr;
    path = addr->name[0].sun_path;
    __FILTER__

    addr = ((struct unix_sock *)((struct unix_sock *)sock->sk)->peer)->addr;
    path = addr->name[0].sun_path;
    __FILTER__

    if (match == 0)
        return 0;

    n = 0;
    packet = packet_array.lookup(&n);
    if (packet == NULL)
        return 0;

    packet->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&packet->comm, sizeof(packet->comm));

    iter = &msg->msg_iter;
    if (iter->type != WRITE || iter->iov_offset != 0) {
        packet->len = len;
        packet->flags = SS_PACKET_F_ERR;
        events.perf_submit(ctx, packet, offsetof(struct packet, data));
        return 0;
    }

    iov = iter->kvec;

    #pragma unroll
    for (int i = 0; i < SS_MAX_NR_SEGS; i++) {
        if (i >= iter->nr_segs)
            break;

        packet->len = iov->iov_len;
        packet->flags = 0;

        buf = iov->iov_base;
        n = iov->iov_len;
        bpf_probe_read(
            &packet->data,
            // check size in args to make compiler/validator happy
            n > sizeof(packet->data) ? sizeof(packet->data) : n,
            buf);

        n += offsetof(struct packet, data);
        events.perf_submit(
            ctx,
            packet,
            // check size in args to make compiler/validator happy
            n > sizeof(*packet) ? sizeof(*packet) : n);

        iov++;
    }

    return 0;
}
'''

TASK_COMM_LEN = 16
UNIX_PATH_MAX = 108

SS_MAX_SEG_SIZE = 1024 * 1024
SS_MAX_NR_SEGS = 10

SS_PACKET_F_ERR = 1

class Packet(ct.Structure):
    _fields_ = [
        ('pid', ct.c_uint),
        ('len', ct.c_uint),
        ('flags', ct.c_uint),
        ('comm', ct.c_char * TASK_COMM_LEN),
        ('data', ct.c_char * SS_MAX_SEG_SIZE),
    ]

def render_text(bpf_text, seg_size, nr_segs, filter):
    replaces = {
        '__SS_MAX_SEG_SIZE__': seg_size,
        '__SS_MAX_NR_SEGS__': nr_segs,
        '__FILTER__': filter,
    }
    for k, v in replaces.items():
        bpf_text = bpf_text.replace(k, str(v))
    return bpf_text

# FIXME: optimize filter
def build_filter(sock_path):
    sock_path = sock_path.encode() + b'\0'
    n = len(sock_path)
    if n > UNIX_PATH_MAX:
        raise ValueError('invalid path')

    filter = 'if ('
    filter += ' && '.join(
        '*(path+%d) == %d' % (i, sock_path[i]) for i in range(n))
    filter += ') match = 1;'

    return filter

def string_output(cpu, event, size):
    packet = ct.cast(event, ct.POINTER(Packet)).contents
    print('>>> %s[%d] len %d' % (packet.comm.decode(), packet.pid, packet.len))
    if packet.flags & SS_PACKET_F_ERR:
        print('error')
    else:
        print(packet.data[:packet.len].decode(), end='', flush=True)

# FIXME: hexl and pcap output
outputs = {
    'string': string_output,
}

def main(args):
    filter = build_filter(args.sock)
    text = render_text(bpf_text, args.seg_size, args.nr_segs, filter)
    b = BPF(text=text)
    b.attach_kprobe(
        event='unix_stream_sendmsg', fn_name='probe_unix_stream_sendmsg')

    npages = args.seg_size / resource.getpagesize()
    npages = math.ceil(npages) * args.buffer_nseg
    npages = 2 ** math.ceil(math.log(npages, 2))

    output_fn = outputs[args.output]
    b['events'].open_perf_buffer(output_fn, page_cnt=npages)
    while 1:
        b.perf_buffer_poll()

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Dump unix domain socket traffic')
    parser.add_argument(
        '--seg-size', type=int, default=SS_MAX_SEG_SIZE,
        help='max segment size')
    parser.add_argument(
        '--nr-segs', type=int, default=SS_MAX_NR_SEGS,
        help='max number of iovec segments')
    parser.add_argument(
        '--buffer-nseg', type=int, default=10,
        help='max number of segments in buffer')
    parser.add_argument(
        '--output', choices=outputs.keys(), default='string',
        help='output format')
    parser.add_argument(
        'sock',
        help='unix socket path')
    args = parser.parse_args()
    main(args)
