#!/usr/bin/python3
import sys
import time
import math
import struct
import signal
import resource
import ctypes as ct
import multiprocessing

from bcc import BPF

bpf_text = '''
#include <linux/sched.h>
#include <linux/net.h>
#include <uapi/linux/un.h>
#include <net/af_unix.h>
#include <linux/version.h>

#define SS_MAX_SEG_SIZE     __SS_MAX_SEG_SIZE__
#define SS_MAX_SEGS_PER_MSG __SS_MAX_SEGS_PER_MSG__

#define SS_PACKET_F_ERR     1

#define SOCK_PATH_OFFSET    \
    (offsetof(struct unix_address, name) + offsetof(struct sockaddr_un, sun_path))

struct packet {
    u32 pid;
    u32 peer_pid;
    u32 len;
    u32 flags;
    char comm[TASK_COMM_LEN];
    char path[UNIX_PATH_MAX];
    char data[SS_MAX_SEG_SIZE];
};

// use regular array instead percpu array because
// percpu array element size cannot be larger than 3k
BPF_ARRAY(packet_array, struct packet, __NUM_CPUS__);
BPF_PERF_OUTPUT(events);

int probe_unix_socket_sendmsg(struct pt_regs *ctx,
                              struct socket *sock,
                              struct msghdr *msg,
                              size_t len)
{
    struct packet *packet;
    struct unix_address *addr;
    char *buf, *sock_path;
    unsigned long path[__PATH_LEN_U64__] = {0};
    unsigned int n, match = 0, offset;
    struct iov_iter *iter;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    const struct iovec *iov;
#else
    const struct kvec *iov;
#endif
    struct pid *peer_pid;

    addr = ((struct unix_sock *)sock->sk)->addr;
    if (addr->len > 0) {
        sock_path = (char *)addr + SOCK_PATH_OFFSET;
        if (*sock_path == 0) {
            // abstract sockets start with \\0 and the name comes after
            // (they actually have no @ prefix but some tools use that)
            bpf_probe_read(&path, __PATH_LEN__ - 1, sock_path + 1);
        } else {
            bpf_probe_read(&path, __PATH_LEN__, sock_path);
        }
        __PATH_FILTER__
    }

    addr = ((struct unix_sock *)((struct unix_sock *)sock->sk)->peer)->addr;
    if (match == 0 && addr->len > 0) {
        sock_path = (char *)addr + SOCK_PATH_OFFSET;
        if (*sock_path == 0) {
            // abstract sockets start with \\0 and the name comes after
            // (they actually have no @ prefix but some tools use that)
            bpf_probe_read(&path, __PATH_LEN__ - 1, sock_path + 1);
        } else {
            bpf_probe_read(&path, __PATH_LEN__, sock_path);
        }
        __PATH_FILTER__
    }

    if (match == 0)
        return 0;

    n = bpf_get_smp_processor_id();
    packet = packet_array.lookup(&n);
    if (packet == NULL)
        return 0;

    packet->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&packet->comm, sizeof(packet->comm));
    bpf_probe_read(&packet->path, UNIX_PATH_MAX, sock_path);
    packet->peer_pid = sock->sk->sk_peer_pid->numbers->nr;

    iter = &msg->msg_iter;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    if (iter->iter_type == ITER_UBUF) {
        packet->len = len;
        packet->flags = 0;
        buf = iter->ubuf;
        n = len;

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

        return 0;
    }

    if (iter->iter_type != ITER_IOVEC || iter->iov_offset != 0) {
#else
    if (iter->iov_offset != 0) {
#endif
        packet->len = len;
        packet->flags = SS_PACKET_F_ERR;
        events.perf_submit(ctx, packet, offsetof(struct packet, data));
        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
    iov = iter->__iov;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    iov = iter->iov;
#else
    iov = iter->kvec;
#endif

    #pragma unroll
    for (int i = 0; i < SS_MAX_SEGS_PER_MSG; i++) {
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

SS_MAX_SEG_SIZE = 1024 * 50
SS_MAX_SEGS_PER_MSG = 10
SS_MAX_SEGS_IN_BUFFER = 100

SS_PACKET_F_ERR = 1

def render_text(bpf_text, seg_size, segs_per_msg, sock_path):
    path_filter, path_len, path_len_u64 = build_filter(sock_path)
    replaces = {
        '__SS_MAX_SEG_SIZE__': seg_size,
        '__SS_MAX_SEGS_PER_MSG__': segs_per_msg,
        '__NUM_CPUS__': multiprocessing.cpu_count(),
        '__PATH_LEN__': path_len,
        '__PATH_LEN_U64__': max(path_len_u64, 1),
        '__PATH_FILTER__': path_filter,
    }
    for k, v in replaces.items():
        bpf_text = bpf_text.replace(k, str(v))
    return bpf_text

def build_filter(sock_path):
    sock_path_bytes = sock_path.encode()
    # if path ends with * - use prefix-based matching
    if sock_path[-1] == "*":
        sock_path_bytes = sock_path_bytes[:-1]
    elif sock_path[0] == "@":
        sock_path_bytes = sock_path_bytes[1:] + b'\0'
    else:
        sock_path_bytes += b'\0'

    path_len = len(sock_path_bytes)
    if path_len > UNIX_PATH_MAX:
        raise ValueError('invalid path')
    # match all paths
    if path_len == 0:
        return 'match = 1;', 0, 0

    path_len_u64 = (path_len + 7) // 8
    sock_path_bytes += b'\0' * (path_len_u64 * 8 - path_len)
    sock_path_u64s = [
        struct.unpack('Q', sock_path_bytes[i*8:(i+1)*8])[0]
        for i in range(path_len_u64)
    ]

    filter = 'if ('
    filter += ' && '.join(
        'path[{}] == {}'.format(i, n)
        for (i, n) in enumerate(sock_path_u64s)
    )
    filter += ') match = 1;'

    return filter, path_len, path_len_u64

class Packet(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ('pid', ct.c_uint),
        ('peer_pid', ct.c_uint),
        ('len', ct.c_uint),
        ('flags', ct.c_uint),
        ('comm', ct.c_char * TASK_COMM_LEN),
        ('path', ct.c_char * UNIX_PATH_MAX),
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
    ts = time.strftime('%H:%M:%S', time.localtime(ts)) + '.%03d' % (ts%1 * 1000)

    print('%s >>> process %s [%d -> %d] path %s len %d(%d)' % (
        ts, packet.comm.decode(), packet.pid, packet.peer_pid,
        packet.path.decode(), len(data), packet.len))

def string_output(cpu, event, size):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    if packet.flags & SS_PACKET_F_ERR:
        print('error')
    print(str(data.raw, encoding='ascii', errors='ignore'), end='', flush=True)

def ascii(c):
    if c < 32 or c > 126:
        return '.'
    return chr(c)

def hex_print(data):
    for i in range(0, len(data), 16):
        line = '{:04x}'.format(i)
        line += '  '
        line += '{:<23s}'.format(' '.join('%02x' % x for x in data[i:i+8]))
        line += '  '
        line += '{:<23s}'.format(' '.join('%02x' % x for x in data[i+8:i+16]))
        line += '  '
        line += ''.join(ascii(x) for x in data[i:i+16])
        print(line)

def hexstring_print(data):
    chunks = ['\\x{:02x}'.format(i) for i in bytes(data)]
    print(''.join(chunks))

def hex_output(cpu, event, size):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    if packet.flags & SS_PACKET_F_ERR:
        print('error')
    hex_print(data)

def hexstring_output(cpu, event, size):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    if packet.flags & SS_PACKET_F_ERR:
        print('error')
    hexstring_print(data)

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
    header = struct.pack('>QQ', packet.peer_pid, packet.pid)

    data = header + data
    size = len(header) + packet.len
    pcap_write_record(ts_sec, ts_usec, size, data)

outputs = {
    'hex': hex_output,
    'hexstring': hexstring_output,
    'string': string_output,
    'pcap': pcap_output,
}

def sig_handler(signum, stack):
    print('\n%d packets captured' % packet_count, file=sys.stderr)
    sys.exit(signum)

def main(args):
    text = render_text(bpf_text, args.seg_size, args.segs_per_msg, args.sock)

    if args.bpf:
        print(text)
        return

    if args.disassemble:
        BPF(text=text, debug=8)
        return

    b = BPF(text=text)
    b.attach_kprobe(
        event='unix_stream_sendmsg', fn_name='probe_unix_socket_sendmsg')
    b.attach_kprobe(
        event='unix_dgram_sendmsg', fn_name='probe_unix_socket_sendmsg')

    npages = args.seg_size * args.segs_in_buffer / resource.getpagesize()
    npages = 2 ** math.ceil(math.log(npages, 2))

    output_fn = outputs[args.format]
    b['events'].open_perf_buffer(output_fn, page_cnt=npages)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    if args.format == 'pcap':
        sys.stdout = open(args.output, 'wb')
        pcap_write_header(args.seg_size, PCAP_LINK_TYPE)
    else:
        if args.output != '/dev/stdout':
            sys.stdout = open(args.output, 'w')

    print('waiting for data', file=sys.stderr)
    while 1:
        b.perf_buffer_poll()

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Dump unix domain socket traffic')
    parser.add_argument(
        '--seg-size', type=int, default=SS_MAX_SEG_SIZE,
        help='max segment size, increase this number'
             ' if packet size is longer than captured size')
    parser.add_argument(
        '--segs-per-msg', type=int, default=SS_MAX_SEGS_PER_MSG,
        help='max number of iovec segments')
    parser.add_argument(
        '--segs-in-buffer', type=int, default=SS_MAX_SEGS_IN_BUFFER,
        help='max number of segs in perf event buffer,'
             ' increase this number if message is dropped')
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
        '--disassemble', action='store_true',
        help=argparse.SUPPRESS)
    parser.add_argument(
        'sock',
        help=" ".join([
            "unix socket path.",
            "Matches all sockets starting with given path if it ends with \'*\'.",
            "Note that the path must be the same string used in the application,",
            "instead of the actual file path.",
            "If the application used a relative path, the same relative path should be used.",
            "If the application runs inside a container, the path inside the container should be used.",
        ]))
    args = parser.parse_args()
    main(args)
