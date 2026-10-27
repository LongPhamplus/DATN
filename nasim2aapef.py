#!/usr/bin/env python3
"""nasim2aapef.py - Chuyển cấu hình mạng NASim (.yaml, vd small.yaml) sang kịch bản JSON AAPEF.

Đầu ra bám template scenarios/template/aapef_template.json (loader: aapef/scenario.py).
Chỉ dùng thư viện chuẩn (không cần PyYAML): có bộ đọc YAML con đủ cho định dạng NASim.

Ánh xạ NASim -> AAPEF
  subnet 0 (Internet)        -> host ảo ATK (access = user) làm điểm xuất phát.
  host (s, i)                -> host "H{s}_{i}" với os/services lấy từ host_configurations.
  topology                   -> cạnh có hướng [a, b] nếu cùng subnet hoặc ma trận topology nối hai subnet
                                (không xét firewall, như quét của NASim).
  firewall                   -> Template chỉ có 'reachable' không gắn service, nên ràng buộc theo
                                service được mã hoá vào TỪNG action exploit: chỉ sinh exploit (src, dst)
                                khi firewall cho đúng service của exploit đi qua.
  subnet_scan                -> discover_{src}_S{n}: learn k_{host} cho mọi host trong subnet n.
                                Host thuộc subnet nối Internet có sẵn trong initial_state.known
                                (như network.reset của NASim) nên không sinh quét thừa cho chúng.
  exploit e                  -> e_{src}_to_{dst}: cần access user trên src, reachable, known k_{dst},
                                env_fact vuln_{dst}_{e} (host chạy đúng service và khớp OS).
                                access user -> set_access user; access root -> set_access admin.
  privilege_escalation pe    -> pe_{host}: cần access user + env_fact vuln_{host}_{pe}; set admin.
  sensitive_hosts            -> goal admin. Có >= 2 host nhạy cảm: thêm host ảo GOAL và action
                                capture_all (cost 0) cần admin trên TẤT CẢ host nhạy cảm.

Đơn giản hoá (AAPEF tất định, ít loại scan hơn NASim)
  * prob bị gộp vào cost: cost' = max(1, round(cost / prob)) (số lần thử kỳ vọng); --ignore-prob giữ nguyên cost.
    prob gốc vẫn được chép nguyên vào trường 'prob' của mọi action e_* / pe_* (mô hình 'native',
    aapef/prob.py); discover_* và capture_all không mang 'prob'.
  * service_scan/os_scan/process_scan_cost không được mô hình hoá (không có action tương ứng);
    chi phí discover = subnet_scan_cost.
  * giá trị thưởng của sensitive_hosts chỉ còn là tập đích, không có điểm số.

Ví dụ:
  python nasim2aapef.py small.yaml
  python nasim2aapef.py small.yaml -o scenarios/small.json --id nasim-small-01
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ATTACKER = "ATK"
VIRTUAL_GOAL = "GOAL"
DEFAULT_OUT_DIR = "scenarios"
WELL_KNOWN_PORTS = {"ssh": 22, "ftp": 21, "http": 80, "https": 443, "smtp": 25,
                    "samba": 445, "smb": 445, "rdp": 3389, "telnet": 23}


class ConvertError(Exception):
    """Lỗi đọc hoặc chuyển đổi cấu hình NASim."""


# ----------------------------------------------------------------------------
# Bộ đọc YAML con (map lồng nhau, list "- x", list inline "[a, b]", scalar, khoá tuple "(1, 0)")
# ----------------------------------------------------------------------------
def _scalar(text: str) -> Any:
    t = text.strip()
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        parts, depth, cur = [], 0, ""
        for ch in inner:  # tách theo dấu phẩy ngoài cùng (list lồng nhau)
            depth += (ch == "[") - (ch == "]")
            if ch == "," and depth == 0:
                parts.append(cur)
                cur = ""
            else:
                cur += ch
        parts.append(cur)
        return [_scalar(x) for x in parts] if inner else []
    if t in ("None", "null", "~", ""):
        return None
    if t in ("True", "true"):
        return True
    if t in ("False", "false"):
        return False
    for cast in (int, float):
        try:
            return cast(t)
        except ValueError:
            pass
    return t.strip("'\"")


def _split_key(content: str) -> Tuple[str, str]:
    m = re.match(r"^(.*?):(?:\s+(.*))?$", content)
    if not m:
        raise ConvertError(f"Dòng YAML không hợp lệ: {content!r}")
    return m.group(1).strip(), (m.group(2) or "").strip()


def pending_indent_line(joined: str) -> Tuple[int, str]:
    return len(joined) - len(joined.lstrip(" ")), joined.strip()


def parse_yaml(text: str) -> Dict[str, Any]:
    lines: List[Tuple[int, str]] = []
    pending = ""  # list inline trải nhiều dòng: gộp tới khi cân ngoặc
    for raw in text.splitlines():
        body = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if not body.strip():
            continue
        if pending:
            pending += " " + body.strip()
            if pending.count("[") <= pending.count("]"):
                lines.append(pending_indent_line(pending))
                pending = ""
            continue
        if body.count("[") > body.count("]"):
            pending = body
            continue
        lines.append((len(body) - len(body.lstrip(" ")), body.strip()))
    if pending:
        raise ConvertError("List inline YAML không đóng ngoặc.")

    def block(i: int, indent: int) -> Tuple[Any, int]:
        if lines[i][1].startswith("- "):
            items = []
            while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
                items.append(_scalar(lines[i][1][2:]))
                i += 1
            return items, i
        mapping: Dict[str, Any] = {}
        while i < len(lines) and lines[i][0] == indent:
            key, val = _split_key(lines[i][1])
            i += 1
            if val:
                mapping[key] = _scalar(val)
            elif i < len(lines) and lines[i][0] > indent:
                mapping[key], i = block(i, lines[i][0])
            else:
                mapping[key] = None
        return mapping, i

    if not lines:
        raise ConvertError("File YAML rỗng.")
    data, end = block(0, lines[0][0])
    if end != len(lines):
        raise ConvertError(f"Thụt lề YAML không nhất quán gần: {lines[end][1]!r}")
    return data


# ----------------------------------------------------------------------------
# Chuyển đổi
# ----------------------------------------------------------------------------
Addr = Tuple[int, int]


def _addr(key: Any) -> Addr:
    m = re.fullmatch(r"\(\s*(\d+)\s*,\s*(\d+)\s*\)", str(key))
    if not m:
        raise ConvertError(f"Khoá địa chỉ host không hợp lệ: {key!r} (cần dạng '(subnet, host)').")
    return int(m.group(1)), int(m.group(2))


def _pair(key: Any) -> Tuple[int, int]:
    return _addr(key)


def _need(cfg: Dict[str, Any], key: str) -> Any:
    if key not in cfg:
        raise ConvertError(f"Thiếu khoá bắt buộc '{key}' trong file NASim.")
    return cfg[key]


def host_id(addr: Addr) -> str:
    return f"H{addr[0]}_{addr[1]}"


def _p_access(host: str, level: str) -> Dict[str, Any]:
    return {"type": "access_at_least", "host": host, "level": level}


def _p_reach(src: str, dst: str) -> Dict[str, Any]:
    return {"type": "reachable", "from": src, "to": dst}


def _cost(base: Any, prob: Any, use_prob: bool) -> int:
    base = float(base)
    if use_prob and prob:
        base /= float(prob)
    return max(1, round(base))


def _prob(name: str, entry: Dict[str, Any]) -> float:
    # Xác suất thành công gốc của NASim, chép nguyên cho mô hình 'native' (aapef/prob.py).
    p = entry.get("prob")
    if isinstance(p, bool) or not isinstance(p, (int, float)) or not 0 <= p <= 1:
        raise ConvertError(f"{name}: cần 'prob' là số trong [0, 1], nhận {p!r}.")
    return float(p)


def convert(cfg: Dict[str, Any], scenario_id: str, use_prob: bool = True) -> Dict[str, Any]:
    sizes: List[int] = list(_need(cfg, "subnets"))
    matrix: List[List[int]] = _need(cfg, "topology")
    if len(matrix) != len(sizes) + 1 or any(len(r) != len(sizes) + 1 for r in matrix):
        raise ConvertError(f"topology phải là ma trận {len(sizes) + 1}x{len(sizes) + 1} (subnet 0 = Internet).")
    sensitive = {_addr(k): v for k, v in (_need(cfg, "sensitive_hosts") or {}).items()}
    if not sensitive:
        raise ConvertError("sensitive_hosts rỗng: không có đích để lập goal.")
    firewall = {_pair(k): list(v or []) for k, v in (cfg.get("firewall") or {}).items()}
    exploits: Dict[str, Dict[str, Any]] = cfg.get("exploits") or {}
    privesc: Dict[str, Dict[str, Any]] = cfg.get("privilege_escalation") or {}
    subnet_scan_cost = cfg.get("subnet_scan_cost", 1)

    # --- host ---
    conf: Dict[Addr, Dict[str, Any]] = {_addr(k): v for k, v in _need(cfg, "host_configurations").items()}
    addrs: List[Addr] = [(s, i) for s, n in enumerate(sizes, start=1) for i in range(n)]
    for a in addrs:
        if a not in conf:
            raise ConvertError(f"host_configurations thiếu host {a}.")
    for a in sensitive:
        if a not in conf:
            raise ConvertError(f"sensitive_hosts tham chiếu host không tồn tại: {a}.")

    hosts: List[Dict[str, Any]] = [
        {"id": ATTACKER, "ip": "10.0.0.1", "hostname": "internet-attacker", "os": "sim-os", "services": []}]
    for a in addrs:
        c = conf[a]
        services = []
        for s in c.get("services") or []:
            entry: Dict[str, Any] = {"name": s, "protocol": "tcp"}
            if s in WELL_KNOWN_PORTS:
                entry["port"] = WELL_KNOWN_PORTS[s]
            services.append(entry)
        hosts.append({"id": host_id(a), "ip": f"10.0.{a[0]}.{a[1] + 1}", "hostname": f"h{a[0]}-{a[1]}",
                      "os": c.get("os") or "sim-os", "services": services})

    node_subnet: Dict[str, int] = {ATTACKER: 0, **{host_id(a): a[0] for a in addrs}}
    ids: List[str] = list(node_subnet)

    # --- cho phép lưu lượng theo subnet / service ---
    def permitted(si: int, sj: int, service: str) -> bool:
        if si == sj:
            return True
        return bool(matrix[si][sj]) and service in firewall.get((si, sj), [])

    def connected(si: int, sj: int) -> bool:
        # Như NASim: quét chỉ cần subnet nối nhau, không phụ thuộc firewall.
        return si == sj or bool(matrix[si][sj])

    topology = [[a, b] for a in ids for b in ids if a != b and connected(node_subnet[a], node_subnet[b])]
    edges = {tuple(e) for e in topology}

    env_facts: List[str] = []

    def env(fact: str) -> str:
        if fact not in env_facts:
            env_facts.append(fact)
        return fact

    actions: List[Dict[str, Any]] = []

    # --- subnet_scan -> discover ---
    members: Dict[int, List[str]] = {s: [host_id(a) for a in addrs if a[0] == s] for s in range(1, len(sizes) + 1)}
    # Như network.reset của NASim: host thuộc subnet nối với Internet đã được khám phá từ đầu.
    known0 = [f"k_{h}" for s, hs in members.items() if matrix[0][s] for h in hs]
    for src in ids:
        for s, hs in members.items():
            probe = next((h for h in hs if h != src), None)
            if probe is None or (src, probe) not in edges:
                continue
            if all(f"k_{h}" in known0 for h in hs):
                continue  # không còn gì để học (vd. quét subnet 1 từ ATK)
            actions.append({
                "id": f"discover_{src}_S{s}", "name": f"Subnet scan of subnet {s} from {src}",
                "preconditions": [_p_access(src, "user"), _p_reach(src, probe)],
                "cost": int(subnet_scan_cost),
                "effects": [{"type": "learn", "fact": f"k_{h}"} for h in hs]})

    # --- exploit ---
    for name, ex in exploits.items():
        service, os_req = ex.get("service"), ex.get("os")
        level = "admin" if ex.get("access") == "root" else "user"
        cost = _cost(ex.get("cost", 1), ex.get("prob"), use_prob)
        prob = _prob(name, ex)
        for dst in addrs:
            c = conf[dst]
            if service not in (c.get("services") or []) or (os_req and c.get("os") != os_req):
                continue
            d = host_id(dst)
            for src in ids:
                if src == d or (src, d) not in edges or not permitted(node_subnet[src], dst[0], service):
                    continue
                actions.append({
                    "id": f"{name}_{src}_to_{d}", "name": f"{name} ({service}) from {src} on {d}",
                    "preconditions": [_p_access(src, "user"), _p_reach(src, d),
                                      {"type": "known", "fact": f"k_{d}"},
                                      {"type": "env_fact", "fact": env(f"vuln_{d}_{name}")}],
                    "cost": cost, "prob": prob,
                    "effects": [{"type": "set_access", "host": d, "level": level}]})

    # --- privilege escalation ---
    for name, pe in privesc.items():
        level = "admin" if pe.get("access") == "root" else "user"
        cost = _cost(pe.get("cost", 1), pe.get("prob"), use_prob)
        prob = _prob(name, pe)
        os_req = pe.get("os")
        for dst in addrs:
            c = conf[dst]
            if pe.get("process") not in (c.get("processes") or []) or (os_req and c.get("os") != os_req):
                continue
            d = host_id(dst)
            actions.append({
                "id": f"{name}_{d}", "name": f"{name} ({pe.get('process')}) on {d}",
                "preconditions": [_p_access(d, "user"),
                                  {"type": "env_fact", "fact": env(f"vuln_{d}_{name}")}],
                "cost": cost, "prob": prob,
                "effects": [{"type": "set_access", "host": d, "level": level}]})

    # --- goal ---
    targets = [host_id(a) for a in sorted(sensitive)]
    if len(targets) == 1:
        goal_host = targets[0]
    else:
        goal_host = VIRTUAL_GOAL
        hosts.append({"id": VIRTUAL_GOAL, "ip": "0.0.0.0", "hostname": "virtual-goal",
                      "os": "sim-os", "services": []})
        actions.append({
            "id": "capture_all", "name": "Virtual goal: every sensitive host is owned at admin",
            "preconditions": [_p_access(t, "admin") for t in targets], "cost": 0,
            "effects": [{"type": "set_access", "host": VIRTUAL_GOAL, "level": "admin"}]})

    access = {h["id"]: "none" for h in hosts}
    access[ATTACKER] = "user"
    description = (f"Converted from a NASim configuration ({len(addrs)} hosts in {len(sizes)} subnets plus "
                   f"Internet attacker {ATTACKER}). Sensitive hosts: {', '.join(targets)}"
                   f"{' (aggregated by virtual host ' + VIRTUAL_GOAL + ')' if len(targets) > 1 else ''}. "
                   f"Cost = {'rounded cost/prob (expected attempts)' if use_prob else 'raw cost'}; "
                   f"service/os/process scans and rewards are not modelled.")
    return {
        "scenario_id": scenario_id,
        "description": description,
        "hosts": hosts,
        "topology": topology,
        "env_facts": env_facts,
        "initial_state": {"access": access, "known": known0},
        "actions": actions,
        "goal": _p_access(goal_host, "admin"),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Chuyển NASim .yaml sang kịch bản AAPEF .json.")
    ap.add_argument("input", help="file NASim .yaml (vd small.yaml)")
    ap.add_argument("-o", "--output", help=f"file JSON đầu ra (mặc định {DEFAULT_OUT_DIR}/<tên>.json)")
    ap.add_argument("--id", dest="scenario_id", help="scenario_id (mặc định nasim-<tên file>)")
    ap.add_argument("--ignore-prob", action="store_true", help="không chia cost cho prob")
    args = ap.parse_args(argv)

    src = Path(args.input)
    try:
        cfg = parse_yaml(src.read_text(encoding="utf-8"))
        scenario = convert(cfg, args.scenario_id or f"nasim-{src.stem}", use_prob=not args.ignore_prob)
    except (OSError, ConvertError) as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        return 2

    # Kiểm tra bằng chính loader của engine (nếu chạy trong repo).
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from aapef.scenario import build_scenario
        build_scenario(scenario)
    except ImportError:
        print("Cảnh báo: không import được aapef.scenario, bỏ qua kiểm tra loader.", file=sys.stderr)
    except ValueError as exc:
        print(f"Lỗi: kịch bản sinh ra không qua loader AAPEF: {exc}", file=sys.stderr)
        return 1

    out = Path(args.output) if args.output else Path(DEFAULT_OUT_DIR) / f"{src.stem}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(scenario, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Đã ghi {out}: {len(scenario['hosts'])} host, {len(scenario['topology'])} cạnh, "
          f"{len(scenario['actions'])} action.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
