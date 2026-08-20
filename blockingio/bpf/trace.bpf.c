// trace.bpf.c — blocking I/O detector
//
// 全ての I/O syscall を enter/exit ペアで捕まえ、実際にブロックした時間を測る。
// nonblock は三値 (0=blocking, 1=nonblock, -1=unknown)。「マップに無い」を
// 「ブロッキング」と解釈しないのが誤検知を防ぐ要点。
//
// Python 側 (blockingio/runtime.py の substitute) が以下を置換する:
//   {USE_PID_FILTER} {TARGET_PID} {TARGET_COMM} {MIN_LATENCY_NS}
//   {STALL_LATENCY_NS} {TRACE_FILE_IO} {TRACE_WAIT} {REQUIRE_LOOP_THREAD}
// 置換前のこのファイルは valid な C ではないので、単体でのコンパイルはできない。

#include <uapi/linux/ptrace.h>
#include <uapi/linux/fcntl.h>
#include <uapi/linux/unistd.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/netlink.h>
#include <linux/sched.h>

// op codes: 0:sendto 1:recvfrom 2:sendmsg 3:recvmsg 4:write 5:read 6:connect
// 7:accept4 8:close 9:readv 10:writev 11:epoll_wait 12:poll 13:select
// 14:openat 15:fsync 16:fdatasync
// blockingio/event.py の OPS と同じ順序。tests/test_ops.py が一致を検証する。
#define OP_SENDTO     0
#define OP_RECVFROM   1
#define OP_SENDMSG    2
#define OP_RECVMSG    3
#define OP_WRITE      4
#define OP_READ       5
#define OP_CONNECT    6
#define OP_ACCEPT4    7
#define OP_CLOSE      8
#define OP_READV      9
#define OP_WRITEV     10
#define OP_EPOLL_WAIT 11
#define OP_POLL       12
#define OP_SELECT     13
#define OP_OPENAT     14
#define OP_FSYNC      15
#define OP_FDATASYNC  16

// verdict: blockingio/event.py の Verdict と一致させる。
#define V_OK    0
#define V_IDLE  1
#define V_WARN  2
#define V_STALL 3

// nonblock 三値
#define NB_BLOCKING 0
#define NB_NONBLOCK 1
#define NB_UNKNOWN  (-1)

// マジックナンバーの名前付け
#define MSG_DONTWAIT_FLAG 0x40
#define FIONBIO_REQ       0x5421
#define EPOLL_CTL_ADD_OP  1
#define EPOLL_CTL_DEL_OP  2
#define SOCK_NONBLOCK_FLAG 0x800  // x86_64 では O_NONBLOCK と同値だが別概念
#define EINPROGRESS_RET (-115)    // 非ブロッキング connect の正常系

// 表示閾値と STALL 判定閾値は独立させる。同一にすると --min-latency 0 が
// 「全て表示」と「全てのブロッキング I/O を STALL 扱い」を同時に意味してしまう。
#define MIN_LATENCY_NS ((u64){MIN_LATENCY_NS})
#define STALL_NS       ((u64){STALL_LATENCY_NS})

struct key_t { u32 pid; int fd; };

struct io_evt_t {
    u64 ts;
    u64 duration_ns;
    s64 ret;
    u32 pid;
    u32 tid;
    char comm[16];
    int fd;
    int op;
    int nonblock;
    int via_epoll;
    int msg_dontwait;
    int verdict;
    u16 family;
    u16 rport;
    u32 raddr4;
    unsigned char raddr6[16];
};

struct peer_t { u16 family; u16 rport; u32 raddr4; unsigned char raddr6[16]; };

// 全 op 共通の enter コンテキスト。1 スレッドが同時に 2 つの syscall に入る
// ことはないので pid_tgid キーで足りる。pid 単独ではマルチスレッド asyncio で
// 衝突するので不可。
struct io_start_t {
    u64  ts;
    void *addr;   // sendto/recvfrom: sockaddr* / sendmsg/recvmsg: msghdr* / 他: NULL
    int  fd;
    int  op;
    int  msg_dontwait;
    int  have_peer;          // enter 時点で peer を解決できたか
    struct peer_t peer;      // 解決済み peer
};

struct connect_ctx_t { int fd; void *uaddr; };
struct accept_ctx_t  { void *upeer; int flags; };
struct fcntl_ctx_t   { int fd; int cmd; };

BPF_LRU_HASH(fd_nonblock, struct key_t, u8, 65536);
BPF_LRU_HASH(fd_epoll,    struct key_t, u8, 65536);
BPF_LRU_HASH(peer_map,    struct key_t, struct peer_t, 65536);
BPF_HASH(io_start,    u64, struct io_start_t, 16384);
BPF_HASH(connect_ctx, u64, struct connect_ctx_t, 4096);
BPF_HASH(accept_ctx,  u64, struct accept_ctx_t, 4096);
BPF_HASH(fcntl_ctx,   u64, struct fcntl_ctx_t, 4096);
BPF_HASH(sock_flags,  u64, int, 4096);
// epoll_wait を実行したスレッド = イベントループスレッド。
// ThreadPoolExecutor のワーカでのブロッキング I/O を誤検知しないための識別。
// キーは pid_tgid。裸の tid だと Linux が TID を再利用したときに、無関係な
// executor スレッドがイベントループスレッドと誤認され偽の STALL を生む。
BPF_HASH(loop_tid,    u64, u8, 4096);
// 閾値で間引く前の正確な件数。perf buffer を通さずに総数を保つ。
BPF_HASH(op_stats,    u32, u64, 256);
BPF_PERF_OUTPUT(events);

static __always_inline int is_target() {
#if {USE_PID_FILTER}
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != {TARGET_PID}) return 0;
    return 1;
#else
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    const char TARGET_COMM[] = "{TARGET_COMM}";
    if (__builtin_memcmp(comm, TARGET_COMM, sizeof(TARGET_COMM) - 1) != 0) return 0;
    return 1;
#endif
}

static __always_inline int op_is_wait(int op) {
    return op == OP_EPOLL_WAIT || op == OP_POLL || op == OP_SELECT;
}

static __always_inline int op_needs_peer(int op) {
    // read/write/readv/writev は peer_map にある FD のみ報告する。
    // そうしないと通常のファイル I/O で溢れる。
    return op == OP_READ || op == OP_WRITE || op == OP_READV || op == OP_WRITEV;
}

static __always_inline void fill_state(struct io_evt_t *e) {
    // 既定は unknown。マップに無いことを「ブロッキング」と解釈しない。
    e->nonblock = NB_UNKNOWN;
    e->via_epoll = 0;
    // epoll_wait/poll/select/openat は fd を持たず -1 を入れている。
    // そのまま引くと {pid,-1} を複数の op で共有してしまうので引かない。
    if (e->fd < 0) return;

    struct key_t key = {.pid = e->pid, .fd = e->fd};
    u8 *v;
    v = fd_nonblock.lookup(&key);
    if (v) e->nonblock = *v ? NB_NONBLOCK : NB_BLOCKING;
    v = fd_epoll.lookup(&key);
    if (v && *v) e->via_epoll = 1;
}

// sockaddr -> peer_t。io_evt_t(96B) をスクラッチに使わずに済むよう分離した。
static __always_inline void read_peer(struct peer_t *p, const void *uaddr) {
    if (!uaddr) { p->family = 0; p->rport = 0; p->raddr4 = 0; return; }
    sa_family_t fam = 0;
    bpf_probe_read_user(&fam, sizeof(fam), uaddr);
    if (fam == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), uaddr);
        p->family = AF_INET; p->rport = sin.sin_port; p->raddr4 = sin.sin_addr.s_addr;
    } else if (fam == AF_INET6) {
        struct sockaddr_in6 s6 = {};
        bpf_probe_read_user(&s6, sizeof(s6), uaddr);
        p->family = AF_INET6; p->rport = s6.sin6_port;
        __builtin_memcpy(p->raddr6, &s6.sin6_addr.s6_addr, 16);
    } else if (fam == AF_NETLINK) {
        struct sockaddr_nl snl = {};
        bpf_probe_read_user(&snl, sizeof(snl), uaddr);
        p->family = AF_NETLINK; p->raddr4 = snl.nl_pid;
        p->rport = (u16)(snl.nl_groups & 0xFFFF);
    } else {
        p->family = fam;
    }
}

static __always_inline void fill_remote_from_sockaddr(struct io_evt_t *e, const void *uaddr) {
    struct peer_t p = {};
    read_peer(&p, uaddr);
    e->family = p.family; e->rport = p.rport; e->raddr4 = p.raddr4;
    __builtin_memcpy(e->raddr6, p.raddr6, 16);
}

static __always_inline int fill_remote_from_peer_map(struct io_evt_t *e) {
    struct key_t key = {.pid = e->pid, .fd = e->fd};
    struct peer_t *pp = peer_map.lookup(&key);
    if (!pp) return 0;
    e->family = pp->family; e->rport = pp->rport; e->raddr4 = pp->raddr4;
    __builtin_memcpy(e->raddr6, pp->raddr6, 16);
    return 1;
}

static __always_inline void remember_peer(u32 pid, int fd, struct io_evt_t *e) {
    struct peer_t p = {.family = e->family, .rport = e->rport, .raddr4 = e->raddr4};
    __builtin_memcpy(p.raddr6, e->raddr6, 16);
    struct key_t key = {.pid = pid, .fd = fd};
    peer_map.update(&key, &p);
}

// 判定。規則: epoll に登録されていないブロッキング fd が閾値を超えたら STALL。
// nonblock が unknown のときは決して STALL にしない。
static __always_inline int classify(struct io_evt_t *e) {
    if (op_is_wait(e->op)) return V_IDLE;        // 待機系は長くても正常
    if (e->msg_dontwait)   return V_OK;          // 明示的に待たない指定

    if (e->nonblock == NB_NONBLOCK) {
        // 非ブロッキング fd は原理上長く待たない。長いなら別要因。
        return (e->duration_ns >= STALL_NS * 10) ? V_WARN : V_OK;
    }
    if (e->nonblock == NB_UNKNOWN) return V_OK;  // 断定しない

    // nonblock == NB_BLOCKING
    if (e->via_epoll) return V_WARN;             // 矛盾。追跡漏れの可能性
    if (e->duration_ns < STALL_NS) return V_OK;

#if {REQUIRE_LOOP_THREAD}
    // executor ワーカでのブロッキング I/O はそのスレッドの本来の仕事。
    u64 tkey = ((u64)e->pid << 32) | e->tid;
    u8 *is_loop = loop_tid.lookup(&tkey);
    if (!is_loop) return V_OK;
#endif
    return V_STALL;
}

static __always_inline void bump_stats(int op) {
    u32 k = (u32)op;
    u64 zero = 0, *v = op_stats.lookup_or_try_init(&k, &zero);
    if (v) (*v)++;
}

static __always_inline int io_enter(int fd, int op, void *addr, int dontwait) {
    if (!is_target()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    struct io_start_t s = {};
    s.ts = bpf_ktime_get_ns();
    s.fd = fd; s.op = op; s.addr = addr; s.msg_dontwait = dontwait;

    // userspace の sockaddr/msghdr は exit 時には再利用・解放されている
    // ことがある（glibc の recvmsg ラッパ等）。enter のうちに読み切る。
    if (addr) {
        if (op == OP_SENDMSG || op == OP_RECVMSG) {
            struct user_msghdr {
                void *name; int namelen; void *iov; size_t iovlen;
                void *control; size_t controllen; unsigned int flags;
            } m = {};
            bpf_probe_read_user(&m, sizeof(m), addr);
            if (m.flags & MSG_DONTWAIT_FLAG) s.msg_dontwait = 1;
            if (m.name) { read_peer(&s.peer, m.name); s.have_peer = 1; }
        } else {
            read_peer(&s.peer, addr);
            s.have_peer = 1;
        }
    }
    io_start.update(&id, &s);
    return 0;
}

static __always_inline int io_exit(void *ctx, long ret) {
    // ここで is_target() を呼んではいけない。--process-name モードでは comm を
    // 実行時に見るため、threading.Thread(name=...) 等で enter と exit の間に
    // comm が変わると exit が弾かれ、io_start のエントリが残る。残ったエントリは
    // 次の syscall に古い ts と op で誤って紐付く。
    // io_start にエントリがあること自体が「enter が対象だった」証明なので、
    // 下の lookup が十分なフィルタになる。
    // lookup コストを syscall の待ち時間に混ぜないよう、先に時刻を取る。
    u64 now = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    struct io_start_t *s = io_start.lookup(&id);
    if (!s) return 0;

    int op = s->op;
    // 間引く前に数える。総件数は正確なまま、遅いイベントだけが perf buffer の
    // コストを払う。
    bump_stats(op);

    u64 dur = now - s->ts;
    if (dur < MIN_LATENCY_NS) { io_start.delete(&id); return 0; }

    struct io_evt_t e = {};
    e.ts = s->ts;
    e.duration_ns = dur;
    e.ret = ret;
    e.pid = id >> 32;
    e.tid = (u32)id;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.fd = s->fd;
    e.op = op;
    e.msg_dontwait = s->msg_dontwait;

    if (s->have_peer) {
        // enter で解決済み。
        e.family = s->peer.family; e.rport = s->peer.rport;
        e.raddr4 = s->peer.raddr4;
        __builtin_memcpy(e.raddr6, s->peer.raddr6, 16);
    } else if (!fill_remote_from_peer_map(&e) && op_needs_peer(op)) {
        // read/write 系は peer_map に載っている FD のみ報告する。
        io_start.delete(&id);
        return 0;
    }

    fill_state(&e);
    e.verdict = classify(&e);
    events.perf_submit(ctx, &e, sizeof(e));
    io_start.delete(&id);
    return 0;
}

/* ---- 非同期状態の学習: fcntl / ioctl / epoll_ctl ---- */

int uprobe_fcntl(struct pt_regs *ctx, int fd, int cmd, long arg) {
    if (!is_target()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (cmd == F_SETFL) {
        struct key_t key = {.pid = pid, .fd = fd};
        u8 v = ((arg & O_NONBLOCK) == O_NONBLOCK) ? 1 : 0;
        fd_nonblock.update(&key, &v);
    }
    // F_GETFL の戻り値からも学習する。asyncio の setblocking() は
    // F_GETFL -> F_SETFL を踏むので実際に発火する。
    struct fcntl_ctx_t c = {.fd = fd, .cmd = cmd};
    fcntl_ctx.update(&id, &c);
    return 0;
}

int uretprobe_fcntl(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct fcntl_ctx_t *c = fcntl_ctx.lookup(&id);
    if (!c) return 0;
    long ret = PT_REGS_RC(ctx);
    if (c->cmd == F_GETFL && ret >= 0) {
        struct key_t key = {.pid = id >> 32, .fd = c->fd};
        u8 v = (ret & O_NONBLOCK) ? 1 : 0;
        fd_nonblock.update(&key, &v);
    }
    fcntl_ctx.delete(&id);
    return 0;
}

int uprobe_ioctl(struct pt_regs *ctx, int fd, unsigned long req, unsigned long argp) {
    if (!is_target()) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (req == FIONBIO_REQ && argp) {
        int val = 0;
        bpf_probe_read_user(&val, sizeof(val), (void *)argp);
        struct key_t key = {.pid = pid, .fd = fd};
        u8 v = val ? 1 : 0;
        fd_nonblock.update(&key, &v);
    }
    return 0;
}

int uprobe_epoll_ctl(struct pt_regs *ctx, int epfd, int op, int fd, void *ev) {
    if (!is_target()) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {.pid = pid, .fd = fd};
    if (op == EPOLL_CTL_ADD_OP) {
        u8 one = 1;
        fd_epoll.update(&key, &one);
    } else if (op == EPOLL_CTL_DEL_OP) {
        fd_epoll.delete(&key);
    }
    return 0;
}

/* ---- socket() 生成時の SOCK_NONBLOCK ---- */

TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    if (!is_target()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    int type = args->type;
    sock_flags.update(&id, &type);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_socket) {
    u64 id = bpf_get_current_pid_tgid();
    int *t = sock_flags.lookup(&id);
    if (!t) return 0;
    int fd = args->ret;
    if (fd >= 0) {
        struct key_t k = {.pid = id >> 32, .fd = fd};
        u8 v = (*t & SOCK_NONBLOCK_FLAG) ? 1 : 0;
        fd_nonblock.update(&k, &v);
    }
    sock_flags.delete(&id);
    return 0;
}

/* ---- close: マップ寿命の管理 ----
 * これが無いとエントリが漏れ続け、fd が再利用されたときに peer を別の宛先
 * として静かに誤表示する。 */

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    if (!is_target()) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {.pid = pid, .fd = args->fd};
    fd_nonblock.delete(&key);
    fd_epoll.delete(&key);
    peer_map.delete(&key);
    return io_enter(args->fd, OP_CLOSE, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_close) { return io_exit(args, (long)args->ret); }

/* ---- connect: peer 学習 + ブロッキング計測 ---- */

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (!is_target()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    struct connect_ctx_t c = {.fd = args->fd, .uaddr = (void *)args->uservaddr};
    connect_ctx.update(&id, &c);
    return io_enter(args->fd, OP_CONNECT, (void *)args->uservaddr, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
    // is_target() で早期 return しない。ctx マップを確実に削除するため。
    u64 id = bpf_get_current_pid_tgid();
    struct connect_ctx_t *c = connect_ctx.lookup(&id);
    if (c) {
        long ret = (long)args->ret;
        // EINPROGRESS は非ブロッキング connect の正常系なので peer を覚える。
        if (ret == 0 || ret == EINPROGRESS_RET) {
            struct io_evt_t e = {};
            e.pid = id >> 32; e.fd = c->fd;
            fill_remote_from_sockaddr(&e, (const void *)c->uaddr);
            remember_peer(e.pid, c->fd, &e);
        }
        connect_ctx.delete(&id);
    }
    return io_exit(args, (long)args->ret);
}

/* ---- accept4: peer 学習 + 生成時フラグ + ブロッキング計測 ---- */

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    if (!is_target()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    struct accept_ctx_t c = {.upeer = (void *)args->upeer_sockaddr, .flags = args->flags};
    accept_ctx.update(&id, &c);
    return io_enter(args->fd, OP_ACCEPT4, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
    u64 id = bpf_get_current_pid_tgid();
    struct accept_ctx_t *c = accept_ctx.lookup(&id);
    if (c) {
        int newfd = args->ret;
        if (newfd >= 0) {
            u32 pid = id >> 32;
            if (c->upeer) {
                struct io_evt_t e = {};
                e.pid = pid; e.fd = newfd;
                fill_remote_from_sockaddr(&e, (const void *)c->upeer);
                remember_peer(pid, newfd, &e);
            }
            struct key_t k = {.pid = pid, .fd = newfd};
            u8 v = (c->flags & SOCK_NONBLOCK_FLAG) ? 1 : 0;
            fd_nonblock.update(&k, &v);
        }
        accept_ctx.delete(&id);
    }
    return io_exit(args, (long)args->ret);
}

/* ---- sendto / recvfrom ----
 * send()/recv() は x86_64 に syscall が存在せず、glibc が
 * sendto(fd,buf,len,flags,NULL,0) / recvfrom(...,NULL,NULL) に落とすので
 * この 2 つのプローブで既にカバーされている。追加しないこと。 */

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    return io_enter(args->fd, OP_SENDTO, (void *)args->addr,
                    (args->flags & MSG_DONTWAIT_FLAG) ? 1 : 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_sendto) { return io_exit(args, (long)args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    return io_enter(args->fd, OP_RECVFROM, (void *)args->addr,
                    (args->flags & MSG_DONTWAIT_FLAG) ? 1 : 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) { return io_exit(args, (long)args->ret); }

/* ---- sendmsg / recvmsg ---- */

TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
    return io_enter(args->fd, OP_SENDMSG, (void *)args->msg, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_sendmsg) { return io_exit(args, (long)args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg) {
    return io_enter(args->fd, OP_RECVMSG, (void *)args->msg, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg) { return io_exit(args, (long)args->ret); }

/* ---- read / write / readv / writev ----
 * TLS 経由の HTTP も拾う。peer_map にある FD のみ報告する。 */

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    return io_enter(args->fd, OP_WRITE, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_write) { return io_exit(args, (long)args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    return io_enter(args->fd, OP_READ, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_read) { return io_exit(args, (long)args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_writev) {
    return io_enter(args->fd, OP_WRITEV, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_writev) { return io_exit(args, (long)args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_readv) {
    return io_enter(args->fd, OP_READV, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_readv) { return io_exit(args, (long)args->ret); }

/* ---- 待機系 ----
 * asyncio では最も興味深い op。長い epoll_wait はループが正常にアイドルして
 * いるだけなので V_IDLE として区別する。ここを回すスレッドが
 * イベントループスレッドだと識別する材料にもなる。 */

#if {TRACE_WAIT}
TRACEPOINT_PROBE(syscalls, sys_enter_epoll_wait) {
    if (!is_target()) return 0;
    u64 tkey = bpf_get_current_pid_tgid();
    u8 one = 1;
    loop_tid.update(&tkey, &one);
    return io_enter(-1, OP_EPOLL_WAIT, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_epoll_wait) { return io_exit(args, (long)args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_poll) {
    if (!is_target()) return 0;
    u64 tkey = bpf_get_current_pid_tgid();
    u8 one = 1;
    loop_tid.update(&tkey, &one);
    return io_enter(-1, OP_POLL, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_poll) { return io_exit(args, (long)args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_select) {
    return io_enter(-1, OP_SELECT, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_select) { return io_exit(args, (long)args->ret); }
#else
// 待機系を無効にしても、イベントループスレッドの識別だけは残す必要がある。
// これが無いと REQUIRE_LOOP_THREAD が全てを V_OK に落としてしまう。
TRACEPOINT_PROBE(syscalls, sys_enter_epoll_wait) {
    if (!is_target()) return 0;
    u64 tkey = bpf_get_current_pid_tgid();
    u8 one = 1;
    loop_tid.update(&tkey, &one);
    return 0;
}
#endif

/* ---- ファイル I/O ----
 * NFS 上のブロッキング open は古典的な asyncio ストールだが、openat は
 * インタプリタ起動と import で大量発生するのでゲートする。 */

#if {TRACE_FILE_IO}
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    return io_enter(-1, OP_OPENAT, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_openat) { return io_exit(args, (long)args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_fsync) {
    return io_enter(args->fd, OP_FSYNC, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_fsync) { return io_exit(args, (long)args->ret); }

TRACEPOINT_PROBE(syscalls, sys_enter_fdatasync) {
    return io_enter(args->fd, OP_FDATASYNC, NULL, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_fdatasync) { return io_exit(args, (long)args->ret); }
#endif
