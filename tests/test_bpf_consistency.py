"""C と Python の定義が乖離していないことを機械的に検証する。

構造体レイアウトのズレは静かに文字化けした出力を生む最悪の故障モードなので、
テキストとして突き合わせて防ぐ。BPF プログラムは CI でコンパイルできないため、
この 2 つのテストが唯一の自動防御。
"""

import re
from pathlib import Path

from blockingio.event import OPS, IoEvt, Verdict

BPF_SRC = Path(__file__).parent.parent / "blockingio" / "bpf" / "trace.bpf.c"


def source() -> str:
    return BPF_SRC.read_text()


def test_bpf_source_exists():
    assert BPF_SRC.is_file()


def test_op_codes_match_ops_table():
    """C の #define OP_* と event.py の OPS が同じ順序であること。"""
    src = source()
    found = {}
    for m in re.finditer(r"^#define OP_(\w+)\s+(\d+)$", src, re.MULTILINE):
        found[int(m.group(2))] = m.group(1).lower()

    assert found, "no OP_* defines found in trace.bpf.c"
    for code, name in sorted(found.items()):
        assert code < len(OPS), f"OP_{name.upper()}={code} has no entry in OPS"
        assert OPS[code] == name, f"op {code}: C says {name!r}, OPS says {OPS[code]!r}"
    assert len(found) == len(OPS), f"C defines {len(found)} ops but OPS has {len(OPS)}"


def test_op_code_comment_matches_ops_table():
    """先頭の "// op codes:" コメントも一致していること（人間が読む側の防御）。"""
    src = source()
    body = src[src.index("// op codes:") :]
    body = body[: body.index("#define OP_")]
    pairs = re.findall(r"(\d+):(\w+)", body)
    assert pairs, "op codes comment not found"
    for code_s, name in pairs:
        code = int(code_s)
        assert OPS[code] == name, f"comment says {code}:{name}, OPS says {OPS[code]}"


def test_io_evt_field_order_matches_c_struct():
    """struct io_evt_t のフィールド順序が ctypes IoEvt と一致すること。"""
    src = source()
    m = re.search(r"struct io_evt_t \{(.*?)\n\};", src, re.DOTALL)
    assert m, "struct io_evt_t not found"

    c_names = []
    for line in m.group(1).splitlines():
        line = line.split("//")[0].strip()
        if not line or not line.endswith(";"):
            continue
        decl = line[:-1]
        # "char comm[16]" -> comm / "unsigned char raddr6[16]" -> raddr6
        name = decl.split()[-1]
        name = name.split("[")[0].lstrip("*")
        c_names.append(name)

    py_names = [f[0] for f in IoEvt._fields_]
    assert c_names == py_names, (
        f"struct layout mismatch:\n  C:      {c_names}\n  Python: {py_names}"
    )


def test_verdict_values_match_c_defines():
    src = source()
    found = {}
    for m in re.finditer(r"^#define V_(\w+)\s+(\d+)$", src, re.MULTILINE):
        found[m.group(1)] = int(m.group(2))
    assert found, "no V_* defines found"
    for name, value in found.items():
        assert hasattr(Verdict, name), f"Verdict has no member {name}"
        assert Verdict[name].value == value, (
            f"V_{name}: C says {value}, Python says {Verdict[name].value}"
        )
    assert len(found) == len(Verdict)


def test_nonblock_tristate_defines_match():
    src = source()
    from blockingio.event import NB_BLOCKING, NB_NONBLOCK, NB_UNKNOWN

    assert "#define NB_BLOCKING 0" in src
    assert "#define NB_NONBLOCK 1" in src
    assert "#define NB_UNKNOWN  (-1)" in src
    assert (NB_BLOCKING, NB_NONBLOCK, NB_UNKNOWN) == (0, 1, -1)


def test_all_placeholders_are_known():
    """substitute() が埋めるプレースホルダ以外が残っていないこと。"""
    from blockingio import runtime

    src = source()
    placeholders = set(re.findall(r"\{([A-Z_]+)\}", src))
    substituted = runtime.substitute(
        src,
        pid=None,
        process_name="python3",
        min_latency_ns=1_000_000,
        stall_latency_ns=50_000_000,
        trace_file_io=False,
        trace_wait=True,
        all_threads=False,
    )
    leftover = set(re.findall(r"\{([A-Z_]+)\}", substituted))
    assert not leftover, f"unsubstituted placeholders remain: {leftover}"
    assert placeholders, "expected the source to contain placeholders"


def test_send_recv_comment_present():
    """send/recv を「追加し忘れ」だと誤解して足されないようコメントを残す。"""
    src = source()
    assert "send()/recv()" in src
    assert "追加しないこと" in src
