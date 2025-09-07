#!/usr/bin/env python3
import os, sys, platform, argparse
import ctypes as ct
import socket, struct

DEFAULT_BPF_FILE = "trace.bpf.c"


def check_environment(min_kernel=(4, 9)):
    if platform.system() != "Linux":
        print("not support (only Linux is supported)")
        sys.exit(1)
    rel = platform.release().split("-")[0]
    parts = rel.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1] if len(parts) > 1 else 0)
    except ValueError:
        print(f"not support (unknown kernel version: {platform.release()})")
        sys.exit(1)
    if (major, minor) < min_kernel:
        print(f"not support (kernel {major}.{minor} < {min_kernel[0]}.{min_kernel[1]})")
        sys.exit(1)


class IoEvt(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("fd", ct.c_int),
        ("op", ct.c_int),
        ("nonblock", ct.c_int),
        ("via_epoll", ct.c_int),
        ("msg_dontwait", ct.c_int),
        ("family", ct.c_ushort),
        ("rport", ct.c_ushort),
        ("raddr4", ct.c_uint),
        ("raddr6", ct.c_ubyte * 16),
    ]


def ntohs(x):
    return socket.ntohs(x)


def ipv4_ntoa(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", socket.ntohl(n)))


def ipv6_ntoa(b) -> str:
    return socket.inet_ntop(socket.AF_INET6, bytes(b))


def make_print_event(hide_dns=False, hide_netlink=False):
    ops = ["sendto", "recvfrom", "sendmsg", "recvmsg", "write", "read"]

    def print_event(cpu, data, size):
        e = ct.cast(data, ct.POINTER(IoEvt)).contents

        # peer 文字列
        if e.family == socket.AF_INET:
            if hide_dns and ntohs(e.rport) == 53:  # DNSのノイズ抑制（任意）
                return
            peer = f"{ipv4_ntoa(e.raddr4)}:{ntohs(e.rport)}"
        elif e.family == socket.AF_INET6:
            peer = f"[{ipv6_ntoa(e.raddr6)}]:{ntohs(e.rport)}"
        elif e.family == 16:  # AF_NETLINK
            if hide_netlink:
                return
            peer = f"netlink(pid={e.raddr4}, groups={ntohs(e.rport)})"
        elif e.family == 0:
            peer = "-"
        else:
            peer = f"fam={e.family}"

        op_label = ops[e.op] if 0 <= e.op < len(ops) else f"op{e.op}"

        print(
            f"pid={e.pid:>6} comm={e.comm.decode(errors='ignore'):<8} fd={e.fd:<3} "
            f"op={op_label:8} nonblock={e.nonblock} dontwait={e.msg_dontwait} epoll={e.via_epoll} "
            f"peer={peer}"
        )

    return print_event


def find_libc():
    candidates = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib64/libc.so.6",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None


def main():
    parser = argparse.ArgumentParser(description="Python socket tracer (eBPF/BCC)")
    parser.add_argument(
        "-p",
        "--process-name",
        default="python3",
        help="target process name (comm), default: python3",
    )
    parser.add_argument(
        "-b",
        "--bpf-file",
        default=DEFAULT_BPF_FILE,
        help="path to eBPF C source (default: trace.bpf.c)",
    )
    parser.add_argument("--hide-dns", action="store_true", help="hide IPv4:53 lines")
    parser.add_argument(
        "--hide-netlink", action="store_true", help="hide AF_NETLINK lines"
    )
    args = parser.parse_args()

    check_environment(min_kernel=(4, 9))
    from bcc import BPF

    if not os.path.exists(args.bpf_file):
        print(f"not support (BPF source not found: {args.bpf_file})")
        sys.exit(1)

    with open(args.bpf_file, "r") as f:
        src = f.read().replace("{TARGET_COMM}", args.process_name)

    b = BPF(text=src)

    libc = find_libc()
    if not libc:
        print("not support (libc not found)")
        sys.exit(1)

    # attach uprobes
    b.attach_uprobe(name=libc, sym="fcntl", fn_name="uprobe_fcntl")
    b.attach_uprobe(name=libc, sym="ioctl", fn_name="uprobe_ioctl")
    b.attach_uprobe(name=libc, sym="epoll_ctl", fn_name="uprobe_epoll_ctl")

    # perf buffer
    b["events"].open_perf_buffer(make_print_event(args.hide_dns, args.hide_netlink))

    print(
        "Tracing Python socket I/O (connect/accept + sendto/recvfrom + write/read + recvmsg-exit + netlink)… Ctrl-C to stop"
    )
    while True:
        b.perf_buffer_poll()


if __name__ == "__main__":
    main()
