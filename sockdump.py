#!/usr/bin/python
import sys
import time
import math
import struct
import signal
import resource
import ctypes as ct
import multiprocessing

from bcc import BPF

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

// use regular array instead percpu array because
// percpu array element size cannot be larger than 3k
BPF_ARRAY(packet_array, struct packet, __NUM_CPUS__);
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

    n = bpf_get_smp_processor_id();
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
SS_EVENT_BUFFER_SIZE = 16 * 1024 * 1024

SS_PACKET_F_ERR = 1

def render_text(bpf_text, seg_size, nr_segs, filter):
    replaces = {
        '__SS_MAX_SEG_SIZE__': seg_size,
        '__SS_MAX_NR_SEGS__': nr_segs,
        '__NUM_CPUS__': multiprocessing.cpu_count(),
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

class Packet(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ('pid', ct.c_uint),
        ('len', ct.c_uint),
        ('flags', ct.c_uint),
        ('comm', ct.c_char * TASK_COMM_LEN),
        # variable length data
    ]

PCAP_LINK_TYPE = 147    # USER_0

PACKET_SIZE = ct.sizeof(Packet)

packet_count = 0

def parse_event(event, size):
    global packet_count

    packet_count += 1

    packet = ct.cast(event, ct.POINTER(Packet)).contents
    event += PACKET_SIZE

    size -= PACKET_SIZE
    data_len = packet.len
    if  data_len > size:
        data_len = size

    data_type = ct.c_char * data_len
    data = ct.cast(event, ct.POINTER(data_type)).contents

    return packet, data

def print_header(packet, data):
    ts = time.time()
    ts = time.strftime('%H:%M:%S', time.localtime(ts)) + '.%d' % (ts%1 * 1000)

    print('%s >>> process %s[%d] len %d(%d)' % (
        ts, packet.comm.decode(), packet.pid, len(data), packet.len))

def string_output(cpu, event, size):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    if packet.flags & SS_PACKET_F_ERR:
        print('error')
    print(data.decode(), end='', flush=True)

def ascii(c):
    if c < 32 or c > 126:
        return '.'
    return chr(c)

def hex_print(data):
    for i in range(0, len(data), 16):
        line = '%04x  ' % i
        line += ' '.join('%02x' % x for x in data[i:i+8])
        line += '   ' * (8 - len(data[i:i+8]))
        line += '  '
        line += ' '.join('%02x' % x for x in data[i+8:i+16])
        line += '   ' * (8 - len(data[i+8:i+16]))
        line += '  '
        line += ''.join(ascii(x) for x in data[i:i+16])
        print(line)

def hex_output(cpu, event, size):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    if packet.flags & SS_PACKET_F_ERR:
        print('error')
    hex_print(data)

def pcap_write_header(snaplen, network):
    header = struct.pack('=IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, network)
    sys.stdout.write(header)

def pcap_write_record(ts_sec, ts_usec, orig_len, data):
    header = struct.pack('=IIII', ts_sec, ts_usec, len(data), orig_len)
    sys.stdout.write(header)
    sys.stdout.write(data)

def pcap_output(cpu, event, size):
    packet, data = parse_event(event, size)

    ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts % 1) * 10**6)
    header = struct.pack('>QQ', 0, packet.pid)

    data = header + data
    size = len(header) + packet.len
    pcap_write_record(ts_sec, ts_usec, size, data)

outputs = {
    'hex': hex_output,
    'string': string_output,
    'pcap': pcap_output,
}

def sig_handler(signum, stack):
    print('\n%d packets captured' % packet_count, file=sys.stderr)
    sys.exit(signum)

def main(args):
    filter = build_filter(args.sock)
    text = render_text(bpf_text, args.seg_size, args.nr_segs, filter)
    if args.bpf:
        print(text)
        return

    b = BPF(text=text)
    b.attach_kprobe(
        event='unix_stream_sendmsg', fn_name='probe_unix_stream_sendmsg')

    npages = args.buffer_size / resource.getpagesize()
    npages = 2 ** math.ceil(math.log(npages, 2))

    output_fn = outputs[args.format]
    b['events'].open_perf_buffer(output_fn, page_cnt=npages)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    if args.format == 'pcap':
        sys.stdout = open(args.output, 'wb')
        pcap_write_header(args.seg_size, PCAP_LINK_TYPE)
    else:
        sys.stdout = open(args.output, 'w')

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
        '--buffer-size', type=int, default=SS_EVENT_BUFFER_SIZE,
        help='perf event buffer size')
    parser.add_argument(
        '--format', choices=outputs.keys(), default='hex',
        help='output format')
    parser.add_argument(
        '--output', default='/dev/stdout',
        help='output file')
    parser.add_argument(
        '--bpf', action='store_true',
        help=argparse.SUPPRESS)
    parser.add_argument(
        'sock',
        help='unix socket path')
    args = parser.parse_args()
    main(args)
