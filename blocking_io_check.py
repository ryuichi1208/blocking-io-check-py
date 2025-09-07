#!/usr/bin/env python3
import platform
import sys
import ctypes as ct
import os
import socket
import struct

TARGET_COMM = b"python3"  # 例: b"python" に変更可

bpf_src = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/fcntl.h>
#include <uapi/linux/unistd.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/netlink.h>
#include <linux/sched.h>

struct key_t { u32 pid; int fd; };

struct io_evt_t {
    u64 ts;
    u32 pid;
    char comm[16];
    int fd;
    int op;            // 0:sendto 1:recvfrom 2:sendmsg 3:recvmsg
    int nonblock;
    int via_epoll;
    int msg_dontwait;

    u16 family;        // AF_INET / AF_INET6 / AF_NETLINK など
    u16 rport;         // inet: network order / netlink: groups 下位16bit
    u32 raddr4;        // inet: network order / netlink: nl_pid
    unsigned char raddr6[16];
};

struct peer_t {
    u16 family; u16 rport; u32 raddr4; unsigned char raddr6[16];
};
struct recv_ctx_t   { int fd; void *addr; };
struct rmsg_ctx_t   { int fd; void *msg; };
struct connect_ctx_t{ int fd; void *uaddr; int addrlen; };
struct accept_ctx_t { void *upeer; void *upeerlen; };

BPF_HASH(fd_nonblock, struct key_t, u8);
BPF_HASH(fd_epoll,    struct key_t, u8);
BPF_HASH(peer_map,    struct key_t, struct peer_t);
BPF_HASH(recv_ctx,    u64, struct recv_ctx_t);
BPF_HASH(rmsg_ctx,    u64, struct rmsg_ctx_t);
BPF_HASH(connect_ctx, u64, struct connect_ctx_t);
BPF_HASH(accept_ctx,  u64, struct accept_ctx_t);
BPF_PERF_OUTPUT(events);

static __always_inline int is_target() {
    char comm[16]; bpf_get_current_comm(&comm, sizeof(comm));
    const char TARGET_COMM[] = "{TARGET_COMM}";
    if (__builtin_memcmp(comm, TARGET_COMM, sizeof(TARGET_COMM)-1) != 0) return 0;
    return 1;
}
static __always_inline void fill_state(struct io_evt_t *e){
    struct key_t key = {.pid=e->pid, .fd=e->fd};
    u8 *v;
    e->nonblock = 0; e->via_epoll = 0;
    v = fd_nonblock.lookup(&key); if (v && *v) e->nonblock = 1;
    v = fd_epoll.lookup(&key);    if (v && *v) e->via_epoll = 1;
}
static __always_inline void fill_remote_from_sockaddr(struct io_evt_t *e, const void *uaddr){
    if(!uaddr){ e->family=0; e->rport=0; e->raddr4=0; return; }
    sa_family_t fam=0; bpf_probe_read_user(&fam, sizeof(fam), uaddr);
    if(fam==AF_INET){
        struct sockaddr_in sin={}; bpf_probe_read_user(&sin,sizeof(sin),uaddr);
        e->family=AF_INET; e->rport=sin.sin_port; e->raddr4=sin.sin_addr.s_addr;
    }else if(fam==AF_INET6){
        struct sockaddr_in6 s6={}; bpf_probe_read_user(&s6,sizeof(s6),uaddr);
        e->family=AF_INET6; e->rport=s6.sin6_port;
        __builtin_memcpy(e->raddr6, &s6.sin6_addr.s6_addr, 16);
    }else if(fam==AF_NETLINK){
        struct sockaddr_nl snl={}; bpf_probe_read_user(&snl,sizeof(snl),uaddr);
        e->family=AF_NETLINK; e->raddr4=snl.nl_pid; e->rport=(u16)(snl.nl_groups & 0xFFFF);
    }else{
        e->family=fam; // その他は数値のまま
    }
}
static __always_inline int fill_remote_from_peer_map(struct io_evt_t *e){
    struct key_t key={.pid=e->pid, .fd=e->fd};
    struct peer_t *pp=peer_map.lookup(&key);
    if(!pp) return 0;
    e->family=pp->family; e->rport=pp->rport; e->raddr4=pp->raddr4;
    __builtin_memcpy(e->raddr6, pp->raddr6, 16);
    return 1;
}

/* fcntl/ioctl/epoll_ctl（非同期判定用） */
int uprobe_fcntl(struct pt_regs *ctx, int fd, int cmd, long arg){
    if(!is_target()) return 0;
    u32 pid=bpf_get_current_pid_tgid()>>32;
    if(cmd==F_SETFL){
        struct key_t key={.pid=pid,.fd=fd}; u8 one=1,zero=0;
        if((arg & O_NONBLOCK)==O_NONBLOCK) fd_nonblock.update(&key,&one);
        else                               fd_nonblock.update(&key,&zero);
    }
    return 0;
}
int uprobe_ioctl(struct pt_regs *ctx, int fd, unsigned long req, unsigned long argp){
    if(!is_target()) return 0;
    u32 pid=bpf_get_current_pid_tgid()>>32;
    if(req==0x5421 && argp){ // FIONBIO
        int val=0; bpf_probe_read_user(&val,sizeof(val),(void*)argp);
        struct key_t key={.pid=pid,.fd=fd}; u8 one=1,zero=0;
        if(val) fd_nonblock.update(&key,&one); else fd_nonblock.update(&key,&zero);
    }
    return 0;
}
int uprobe_epoll_ctl(struct pt_regs *ctx, int epfd, int op, int fd, void *ev){
    if(!is_target()) return 0;
    if(op==1){ // EPOLL_CTL_ADD
        u32 pid=bpf_get_current_pid_tgid()>>32;
        struct key_t key={.pid=pid,.fd=fd}; u8 one=1;
        fd_epoll.update(&key,&one);
    }
    return 0;
}

/* connect 学習（クライアント） */
TRACEPOINT_PROBE(syscalls, sys_enter_connect){
    if(!is_target()) return 0;
    u64 id=bpf_get_current_pid_tgid();
    struct connect_ctx_t c={.fd=args->fd,.uaddr=(void*)args->uservaddr,.addrlen=args->addrlen};
    connect_ctx.update(&id,&c);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_connect){
    if(!is_target()) return 0;
    u64 id=bpf_get_current_pid_tgid();
    struct connect_ctx_t *c=connect_ctx.lookup(&id);
    if(!c) return 0;
    if((long)args->ret==0){
        struct io_evt_t e={}; e.pid=id>>32; e.fd=c->fd;
        fill_remote_from_sockaddr(&e,(const void*)c->uaddr);
        struct peer_t p={.family=e.family,.rport=e.rport,.raddr4=e.raddr4};
        __builtin_memcpy(p.raddr6,e.raddr6,16);
        struct key_t key={.pid=e.pid,.fd=e.fd}; peer_map.update(&key,&p);
    }
    connect_ctx.delete(&id);
    return 0;
}

/* accept 学習（サーバ） */
TRACEPOINT_PROBE(syscalls, sys_enter_accept4){
    if(!is_target()) return 0;
    u64 id=bpf_get_current_pid_tgid();
    struct accept_ctx_t c={.upeer=(void*)args->upeer_sockaddr,.upeerlen=(void*)args->upeer_addrlen};
    accept_ctx.update(&id,&c);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_accept4){
    if(!is_target()) return 0;
    u64 id=bpf_get_current_pid_tgid();
    struct accept_ctx_t *c=accept_ctx.lookup(&id);
    if(!c) return 0;
    int newfd=args->ret;
    if(newfd>=0 && c->upeer){
        struct io_evt_t e={}; e.pid=id>>32; e.fd=newfd;
        fill_remote_from_sockaddr(&e,(const void*)c->upeer);
        struct peer_t p={.family=e.family,.rport=e.rport,.raddr4=e.raddr4};
        __builtin_memcpy(p.raddr6,e.raddr6,16);
        struct key_t key={.pid=e.pid,.fd=newfd}; peer_map.update(&key,&p);
    }
    accept_ctx.delete(&id);
    return 0;
}

/* sendto / recvfrom */
TRACEPOINT_PROBE(syscalls, sys_enter_sendto){
    if(!is_target()) return 0;
    struct io_evt_t e={};
    char comm[16]; bpf_get_current_comm(&comm,sizeof(comm));
    e.ts=bpf_ktime_get_ns(); e.pid=bpf_get_current_pid_tgid()>>32;
    __builtin_memcpy(e.comm,comm,sizeof(e.comm));
    e.fd=args->fd; e.op=0;
    e.msg_dontwait=(args->flags & 0x40)?1:0; // MSG_DONTWAIT
    if(args->addr) fill_remote_from_sockaddr(&e,(const void*)args->addr);
    else           fill_remote_from_peer_map(&e);
    fill_state(&e);
    events.perf_submit(args,&e,sizeof(e));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom){
    if(!is_target()) return 0;
    u64 id=bpf_get_current_pid_tgid();
    struct recv_ctx_t c={.fd=args->fd,.addr=(void*)args->addr};
    recv_ctx.update(&id,&c);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom){
    if(!is_target()) return 0;
    u64 id=bpf_get_current_pid_tgid();
    struct recv_ctx_t *p=recv_ctx.lookup(&id);
    if(!p) return 0;
    if((long)args->ret>=0){
        struct io_evt_t e={};
        char comm[16]; bpf_get_current_comm(&comm,sizeof(comm));
        e.ts=bpf_ktime_get_ns(); e.pid=id>>32;
        __builtin_memcpy(e.comm,comm,sizeof(e.comm));
        e.fd=p->fd; e.op=1;
        if(p->addr) fill_remote_from_sockaddr(&e,(const void*)p->addr);
        else        fill_remote_from_peer_map(&e);
        fill_state(&e);
        events.perf_submit(args,&e,sizeof(e));
    }
    recv_ctx.delete(&id);
    return 0;
}

/* sendmsg / recvmsg（recvmsg は exit で peer 確定） */
TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg){
    if(!is_target()) return 0;
    struct io_evt_t e={};
    char comm[16]; bpf_get_current_comm(&comm,sizeof(comm));
    e.ts=bpf_ktime_get_ns(); e.pid=bpf_get_current_pid_tgid()>>32;
    __builtin_memcpy(e.comm,comm,sizeof(e.comm));
    e.fd=args->fd; e.op=2;
    struct user_msghdr{ void *name; int namelen; void *iov; size_t iovlen; void *control; size_t controllen; unsigned int flags; } msg={};
    bpf_probe_read_user(&msg,sizeof(msg),(void*)args->msg);
    e.msg_dontwait=(msg.flags & 0x40)?1:0;
    if(msg.name) fill_remote_from_sockaddr(&e,(const void*)msg.name);
    else         fill_remote_from_peer_map(&e);
    fill_state(&e);
    events.perf_submit(args,&e,sizeof(e));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg){
    if(!is_target()) return 0;
    u64 id=bpf_get_current_pid_tgid();
    struct rmsg_ctx_t c={.fd=args->fd,.msg=(void*)args->msg};
    rmsg_ctx.update(&id,&c);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg){
    if(!is_target()) return 0;
    u64 id=bpf_get_current_pid_tgid();
    struct rmsg_ctx_t *p=rmsg_ctx.lookup(&id);
    if(!p) return 0;
    if((long)args->ret>=0){
        struct io_evt_t e={};
        char comm[16]; bpf_get_current_comm(&comm,sizeof(comm));
        e.ts=bpf_ktime_get_ns(); e.pid=id>>32;
        __builtin_memcpy(e.comm,comm,sizeof(e.comm));
        e.fd=p->fd; e.op=3;
        struct user_msghdr{ void *name; int namelen; void *iov; size_t iovlen; void *control; size_t controllen; unsigned int flags; } msg={};
        bpf_probe_read_user(&msg,sizeof(msg),(void*)p->msg);
        if(msg.name) fill_remote_from_sockaddr(&e,(const void*)msg.name);
        else         fill_remote_from_peer_map(&e);
        fill_state(&e);
        events.perf_submit(args,&e,sizeof(e));
    }
    rmsg_ctx.delete(&id);
    return 0;
}

/* ========== read/write (TLS経由のHTTPも拾う) ========= */
/* 注意: ファイルI/Oのノイズを避けるため、peer_map に載っているFDのみ出力 */
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    if (!is_target()) return 0;
    struct io_evt_t e = {};
    e.ts  = bpf_ktime_get_ns();
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.fd  = args->fd;
    e.op  = 4;  // write

    if (!fill_remote_from_peer_map(&e))  // ソケットでなければ無視
        return 0;

    e.msg_dontwait = 0;
    fill_state(&e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    if (!is_target()) return 0;
    struct io_evt_t e = {};
    e.ts  = bpf_ktime_get_ns();
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.fd  = args->fd;
    e.op  = 5;  // read

    if (!fill_remote_from_peer_map(&e))  // ソケットでなければ無視
        return 0;

    e.msg_dontwait = 0;
    fill_state(&e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""


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


def print_event(cpu, data, size):
    e = ct.cast(data, ct.POINTER(IoEvt)).contents
    ops = ["sendto", "recvfrom", "sendmsg", "recvmsg", "write", "read"]
    if e.family == socket.AF_INET:
        peer = f"{ipv4_ntoa(e.raddr4)}:{ntohs(e.rport)}"
    elif e.family == socket.AF_INET6:
        peer = f"[{ipv6_ntoa(e.raddr6)}]:{ntohs(e.rport)}"
    elif e.family == 16:  # AF_NETLINK
        peer = f"netlink(pid={e.raddr4}, groups={ntohs(e.rport)})"
    elif e.family == 0:
        peer = "-"
    else:
        peer = f"fam={e.family}"
    print(
        f"pid={e.pid:>6} comm={e.comm.decode(errors='ignore'):<8} fd={e.fd:<3} "
        f"op={ops[e.op]:8} nonblock={e.nonblock} dontwait={e.msg_dontwait} epoll={e.via_epoll} "
        f"peer={peer}"
    )


def main():
    src = bpf_src.replace("{TARGET_COMM}", TARGET_COMM.decode())
    b = BPF(text=src)

    libc = "/lib/x86_64-linux-gnu/libc.so.6"
    if not os.path.exists(libc):
        for p in [
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/usr/lib64/libc.so.6",
        ]:
            if os.path.exists(p):
                libc = p
                break

    b.attach_uprobe(name=libc, sym="fcntl", fn_name="uprobe_fcntl")
    b.attach_uprobe(name=libc, sym="ioctl", fn_name="uprobe_ioctl")
    b.attach_uprobe(name=libc, sym="epoll_ctl", fn_name="uprobe_epoll_ctl")

    b["events"].open_perf_buffer(print_event)
    print(
        "Tracing Python socket I/O (connect/accept + send/recv + read/write + recvmsg-exit + netlink)… Ctrl-C to stop"
    )
    while True:
        b.perf_buffer_poll()


def check_environment():
    # OS チェック
    if platform.system() != "Linux":
        print("not support (only Linux is supported)")
        sys.exit(1)

    # カーネルバージョンチェック
    release = platform.release()  # 例: "5.15.0-86-generic"
    version_str = release.split("-")[0]  # "5.15.0"
    parts = version_str.split(".")

    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        print(f"not support (unknown kernel version format: {release})")
        sys.exit(1)

    # Linux 4.9 以上を要求
    if (major < 4) or (major == 4 and minor < 9):
        print(f"not support (kernel {major}.{minor} < 4.9)")
        sys.exit(1)

    print(f"Environment OK: Linux kernel {major}.{minor}+ detected")


if __name__ == "__main__":
    check_environment()
    from bcc import BPF
    main()
