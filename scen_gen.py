#!/usr/bin/env python3
"""scenario_generator.py - Sinh kịch bản JSON cho AAPEF (State Planning & Cost Optimization).

Schema bám theo large-01.json / lab-01.json và AAPEF Master Plan v0.4 (§5-§7, §9, §12).

Hai mô hình chi phí (--cost-model):
  * config (PA-A, HỒI QUY): mọi cost lấy ngẫu nhiên theo --seed; bộ sinh ÁP ĐẶT bất biến chi phí
    (direct > tuyến rẻ; lure > direct) để bảo đảm tradeoff RQ1/RQ2 và bẫy Greedy.
  * cvss   (PA-C, CHÍNH):   kịch bản dạng NGUỒN như lab-01 — exploit/privesc mang `cve`, KHÔNG có
    `cost`; chi phí do `python -m aapef recost` tính từ CVSS/CVE (scenarios/cve_catalog.json).
    KHÔNG áp đặt bất biến chi phí: đánh đổi L≠C (nếu có) do cấu trúc + recost quyết định (plan §9.3).

Cấu trúc kịch bản config ("standard"):
  * Host A            : điểm xuất phát (access = user).
  * Chuỗi trung gian  : B, C, ... -> tuyến DÀI nhưng RẺ.
  * Host đích         : cần admin.
  * Dead-end hosts    : có scan + exploit nhưng không dẫn tới đích.
  * Tuyến trực tiếp   : A -> đích, NGẮN nhưng cost RẤT CAO.
  * Greedy lure (tùy) : tuyến đưa goal lên 'user' rồi 'admin' rất đắt, khớp heuristic Greedy.

Cấu trúc kịch bản cvss (bám lab-01):
  entry (user) -> entry-server (initial-access CVE) -> pivot(s) (lateral CVE) -> goal (domain CVE).
  Nếu catalog có CVE privesc: thêm tuyến privesc trên entry-server + pivot admin thẳng tới goal
  (ít hop hơn, là tuyến thay thế ngắn hơn tuyến lateral).

LƯU Ý về mô hình (quan trọng cho --cycles):
  Access chỉ TĂNG (set_access chỉ nâng, không hạ - plan §5.2) và known chỉ thêm. Do đó
  state-space REACHABLE luôn là một ĐỒ THỊ KHÔNG CHU TRÌNH CÓ HƯỚNG (DAG): không tồn tại
  chu trình ở mức state. --cycles KHÔNG tạo cycle state-space; nó chỉ thêm back-edge topology +
  action return_* LUÔN là no-op (đặt lại quyền đã có), bị `successors` loại (plan §7.2); mục đích
  là kiểm thử việc engine loại no-op/self-loop và visited (RQ4). Ở config, cặp shortcut (mid, dst)
  bị loại khỏi back-edge để giữ đúng bất biến "return_* LUÔN no-op".

Ánh xạ tính năng -> câu hỏi nghiên cứu:
  RQ1 (C lệch tối ưu)   : tuyến rẻ vs trực tiếp vs lure; --shortcuts thêm điểm trung gian L/C.
  RQ2 (L lệch tối thiểu): như RQ1, BFS chọn tuyến ít bước nhưng đắt.
  RQ3 (effort theo size): --deadends nhân |V| ~×3; --decoys nhân ~×2; --target-v tự dò |V|; --stats đo |V|,|E|.
  RQ4 (robustness)      : --kind unreachable | initial-goal; --cycles (no-op / back-edge);
                          --greedy-trap (config); --shortcuts (cạnh song song).

Ví dụ:
  python scenario_generator.py --hosts 3 --deadends 1 --verify
  python scenario_generator.py --id trap-01 --hosts 5 --greedy-trap --verify
  python scenario_generator.py --id size-01 --hosts 5 --target-v 500 --stats
  python scenario_generator.py --id gen-cvss-01 --hosts 4 --cost-model cvss --verify --stats
  for v in 100 300 900; do python scenario_generator.py --id size-v$v --hosts 5 --target-v $v --stats; done
"""

from __future__ import annotations

import argparse
import heapq
import json
import random
import re
import sys
from collections import deque
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

# ----------------------------------------------------------------------------
# Hằng số
# ----------------------------------------------------------------------------
DEFAULT_ID = "generated-large-01"
DEFAULT_OUT_DIR = "scenarios"
DEFAULT_MAX_STATES = 200_000
MIN_HOSTS = 3  # entry + >= 1 trung gian + đích

# Khoảng chi phí (mô hình config): lấy ngẫu nhiên theo seed.
SCAN_COST_RANGE = (1, 3)
EXPLOIT_COST_RANGE = (2, 5)
CHEAP_ADMIN_RANGE = (3, 6)
DEADEND_EXPLOIT_RANGE = (2, 4)
LURE_USER_RANGE = (1, 2)   # rẻ -> Greedy bị cám dỗ
RETURN_COST = 1            # no-op dù sao, cost không ảnh hưởng state-space

# Giới hạn khi tự dò --target-v
TUNE_MAX_DEADENDS = 8
TUNE_MAX_DECOYS = 14

LEVELS = {"none": 0, "user": 1, "admin": 2}  # none < user < admin (plan §5.2)
KINDS = ("standard", "unreachable", "initial-goal")

# Plan §6.2 định nghĩa precondition "known"; đổi ở đây nếu engine dùng tên khác.
PRECOND_KNOWN = "known"

# --- Chế độ chi phí & danh mục CVE (plan §9.2-9.3, §6.5) ---
DEFAULT_CVE_CATALOG = "scenarios/cve_catalog.json"
COST_MODELS = ("config", "cvss")

# Vai trò tấn công (plan §9.3). Tên chuẩn hoá nội bộ; catalog có thể dùng alias.
ROLE_INITIAL = "initial-access"
ROLE_LATERAL = "lateral"
ROLE_PRIVESC = "privesc"
ROLE_DOMAIN = "domain-takeover"
ROLE_CLIENT = "client-side"
CANON_ROLES = (ROLE_INITIAL, ROLE_LATERAL, ROLE_PRIVESC, ROLE_DOMAIN, ROLE_CLIENT)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
ROLE_ALIASES = {
    # initial access (RCE từ xa)
    "initial-access": ROLE_INITIAL, "initial_access": ROLE_INITIAL, "initial": ROLE_INITIAL,
    "remote": ROLE_INITIAL, "rce": ROLE_INITIAL, "initial-foothold": ROLE_INITIAL,
    # lateral movement
    "lateral": ROLE_LATERAL, "lateral-movement": ROLE_LATERAL, "lateral_movement": ROLE_LATERAL,
    "pivot": ROLE_LATERAL, "network": ROLE_LATERAL,
    # local privilege escalation
    "privesc": ROLE_PRIVESC, "privilege-escalation": ROLE_PRIVESC, "privilege_escalation": ROLE_PRIVESC,
    "local-privesc": ROLE_PRIVESC, "lpe": ROLE_PRIVESC, "escalation": ROLE_PRIVESC,
    # domain takeover
    "domain-takeover": ROLE_DOMAIN, "domain_takeover": ROLE_DOMAIN, "domain": ROLE_DOMAIN,
    "dc": ROLE_DOMAIN, "domain-admin": ROLE_DOMAIN, "takeover": ROLE_DOMAIN,
    # client-side
    "client-side": ROLE_CLIENT, "client_side": ROLE_CLIENT, "client": ROLE_CLIENT, "phishing": ROLE_CLIENT,
}


class ScenarioError(Exception):
    """Lỗi cấu hình hoặc kịch bản sinh ra không hợp lệ."""


# ----------------------------------------------------------------------------
# Cấu hình
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class ScenarioConfig:
    scenario_id: str = DEFAULT_ID
    hosts: int = MIN_HOSTS
    deadends: int = 1
    seed: int = 42
    shortcuts: int = 0
    cycles: bool = False
    kind: str = "standard"
    shuffle_actions: bool = False
    decoys: int = 0
    greedy_trap: bool = False
    cost_model: str = "config"
    cve_catalog: str = DEFAULT_CVE_CATALOG

    def validate(self) -> None:
        if not self.scenario_id.strip():
            raise ScenarioError("--id không được để trống.")
        if self.hosts < MIN_HOSTS:
            raise ScenarioError(f"--hosts phải >= {MIN_HOSTS} (entry + trung gian + đích).")
        if self.deadends < 0:
            raise ScenarioError("--deadends phải >= 0.")
        if self.decoys < 0:
            raise ScenarioError("--decoys phải >= 0.")
        if self.kind not in KINDS:
            raise ScenarioError(f"--kind phải thuộc {KINDS}.")
        if self.greedy_trap and self.kind != "standard":
            raise ScenarioError("--greedy-trap chỉ áp dụng cho --kind standard (goal phải đạt được).")
        max_shortcuts = self.hosts - 3  # các cặp (Hi, Hi+2) trên đường A..Hk
        if not 0 <= self.shortcuts <= max_shortcuts:
            raise ScenarioError(f"--shortcuts phải trong [0, {max_shortcuts}] với --hosts {self.hosts}.")
        if self.cost_model not in COST_MODELS:
            raise ScenarioError(f"--cost-model phải thuộc {COST_MODELS}.")
        if self.cost_model == "cvss":
            if self.greedy_trap:
                raise ScenarioError("--greedy-trap chỉ dùng với --cost-model config (cần bất biến chi phí; cvss không áp đặt).")
            if self.shortcuts:
                raise ScenarioError("--shortcuts (bỏ host, bất biến chi phí) chỉ dùng với config; cvss dùng tuyến privesc dựng sẵn.")


# ----------------------------------------------------------------------------
# Helper dựng thành phần JSON
# ----------------------------------------------------------------------------
def host_label(index: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA, ..."""
    index += 1
    label = ""
    while index > 0:
        index, rem = divmod(index - 1, 26)
        label = chr(65 + rem) + label
    return label


def p_access(host: str, level: str) -> Dict[str, Any]:
    return {"type": "access_at_least", "host": host, "level": level}


def p_reach(src: str, dst: str) -> Dict[str, Any]:
    return {"type": "reachable", "from": src, "to": dst}


def p_env(fact: str) -> Dict[str, Any]:
    return {"type": "env_fact", "fact": fact}


def p_known(fact: str) -> Dict[str, Any]:
    return {"type": PRECOND_KNOWN, "fact": fact}


def e_learn(fact: str) -> Dict[str, Any]:
    return {"type": "learn", "fact": fact}


def e_access(host: str, level: str) -> Dict[str, Any]:
    return {"type": "set_access", "host": host, "level": level}


def make_action(aid: str, name: str, pre: List[Dict], cost: int, eff: List[Dict]) -> Dict[str, Any]:
    return {"id": aid, "name": name, "preconditions": pre, "cost": cost, "effects": eff}


def make_cve_action(aid: str, name: str, cve: str, pre: List[Dict], eff: List[Dict]) -> Dict[str, Any]:
    # Dạng nguồn CVSS: KHÔNG có 'cost' (recost sẽ tính từ CVSS/CVE). Plan §6.5.
    return {"id": aid, "name": name, "cve": cve, "preconditions": pre, "effects": eff}


def make_learn_action(aid: str, name: str, pre: List[Dict], eff: List[Dict]) -> Dict[str, Any]:
    # Action không gắn CVE (discovery/decoy/return): cũng không có 'cost' ở dạng nguồn.
    return {"id": aid, "name": name, "preconditions": pre, "effects": eff}


# ----------------------------------------------------------------------------
# Bộ sinh kịch bản (mô hình config / PA-A)
# ----------------------------------------------------------------------------
class ScenarioBuilder:
    def __init__(self, config: ScenarioConfig) -> None:
        config.validate()
        self.cfg = config
        self.rng = random.Random(config.seed)

        ids = [host_label(i) for i in range(config.hosts + config.deadends)]
        self.entry: str = ids[0]
        self.chain: List[str] = ids[1 : config.hosts - 1]
        self.goal: str = ids[config.hosts - 1]
        self.dead: List[str] = ids[config.hosts :]
        self.all_ids: List[str] = ids
        self.path: List[str] = [self.entry, *self.chain]  # các host nằm trên đường tới đích
        self.goal_reachable = config.kind != "unreachable"

        self.topology: List[List[str]] = []
        self.env_facts: List[str] = []
        self.actions: List[Dict[str, Any]] = []
        self.dead_parent: Dict[str, str] = {}
        self.shortcut_pairs: List[Tuple[str, str, str]] = []  # (src, mid, dst)
        self.scan_cost: Dict[str, int] = {}
        self.exploit_cost: Dict[str, int] = {}
        self.cheap_admin_cost: Optional[int] = None
        self.cheap_cost: Optional[int] = None
        self.direct_cost: Optional[int] = None
        self.lure_cost: Optional[int] = None

    def _rc(self, rng_range: Tuple[int, int]) -> int:
        return self.rng.randint(rng_range[0], rng_range[1])

    # -- topology (có hướng: reachable from->to cần đúng cạnh [from, to]) ---
    def _build_topology(self) -> None:
        hops = list(zip(self.path, self.path[1:]))
        self.topology = [[a, b] for a, b in hops]
        if self.goal_reachable:
            self.topology.append([self.path[-1], self.goal])
            self.topology.append([self.entry, self.goal])  # đường trực tiếp

        pairs = len(self.path) - 2
        picks = sorted(self.rng.sample(range(pairs), self.cfg.shortcuts)) if pairs > 0 else []
        for i in picks:
            src, mid, dst = self.path[i], self.path[i + 1], self.path[i + 2]
            self.shortcut_pairs.append((src, mid, dst))
            self.topology.append([src, dst])

        if self.cfg.cycles:
            # Back-edge topology: chỉ phục vụ action return_* (no-op). KHÔNG tạo cycle state-space.
            self.topology.extend([b, a] for a, b in hops)

        for d in self.dead:
            parent = self.rng.choice(self.path)
            self.dead_parent[d] = parent
            self.topology.append([parent, d])

    # -- tuyến dài, rẻ ----------------------------------------------------
    def _build_cheap_route(self) -> None:
        prev = self.entry
        total = 0
        for idx, host in enumerate(self.chain, start=1):
            sc = self._rc(SCAN_COST_RANGE)
            ec = self._rc(EXPLOIT_COST_RANGE)
            self.scan_cost[host] = sc
            self.exploit_cost[host] = ec
            self.actions.append(make_action(
                f"scan_{host}", f"Scan {host} (chain hop {idx})",
                [p_access(prev, "user"), p_reach(prev, host)],
                sc, [e_learn(f"k_{host}")]))
            self.actions.append(make_action(
                f"exploit_{host}", f"User on {host} via {prev} (chain hop {idx})",
                [p_access(prev, "user"), p_reach(prev, host),
                 p_known(f"k_{host}"), p_env(f"p_{host}")],
                ec, [e_access(host, "user")]))
            self.env_facts.append(f"p_{host}")
            total += sc + ec
            prev = host

        if self.goal_reachable:
            ca = self._rc(CHEAP_ADMIN_RANGE)
            self.actions.append(make_action(
                f"admin_{self.goal}_from_{prev}",
                f"Admin on {self.goal} via {prev} (cheaper route)",
                [p_access(prev, "user"), p_reach(prev, self.goal), p_env(f"p_{self.goal}")],
                ca, [e_access(self.goal, "admin")]))
            self.env_facts.append(f"p_{self.goal}")
            self.cheap_admin_cost = ca
            self.cheap_cost = total + ca

    # -- tuyến ngắn, đắt --------------------------------------------------
    def _build_direct_route(self) -> None:
        if not self.goal_reachable or self.cheap_cost is None:
            return
        scan_c = self._rc(SCAN_COST_RANGE)
        self.actions.append(make_action(
            f"scan_{self.goal}", f"Scan {self.goal} (direct)",
            [p_access(self.entry, "user"), p_reach(self.entry, self.goal)],
            scan_c, [e_learn(f"k_{self.goal}")]))
        admin_cost = 2 * self.cheap_cost + self.rng.randint(4, 8)
        self.actions.append(make_action(
            f"admin_{self.goal}_direct", f"Admin on {self.goal} directly (short but expensive)",
            [p_access(self.entry, "user"), p_reach(self.entry, self.goal),
             p_known(f"k_{self.goal}"), p_env(f"p_{self.goal}2")],
            admin_cost, [e_access(self.goal, "admin")]))
        self.env_facts.append(f"p_{self.goal}2")
        self.direct_cost = scan_c + admin_cost

    # -- greedy trap: khớp heuristic Greedy (plan §10), dẫn vào tuyến đắt nhất ---
    def _build_greedy_trap(self) -> None:
        if not self.cfg.greedy_trap or not self.goal_reachable or self.cheap_cost is None:
            return
        lure_user_cost = self._rc(LURE_USER_RANGE)
        base = self.direct_cost if self.direct_cost is not None else self.cheap_cost
        admin_from_lure_cost = base + self.rng.randint(3, 8)  # > direct -> tuyến tệ nhất
        self.env_facts.append(f"p_{self.goal}_lure")
        self.env_facts.append(f"p_{self.goal}_lure2")
        # Chỉ hành động này làm goal lên 'user' từ entry -> h giảm 2->1 ngay bước đầu.
        self.actions.append(make_action(
            f"lure_user_{self.goal}", f"Cheap user foothold on {self.goal} (greedy lure)",
            [p_access(self.entry, "user"), p_reach(self.entry, self.goal),
             p_env(f"p_{self.goal}_lure")],
            lure_user_cost, [e_access(self.goal, "user")]))
        # Từ goal=user, hành động này cho h về 0 nhưng rất đắt -> Greedy "ăn" ngay.
        self.actions.append(make_action(
            f"admin_{self.goal}_from_lure",
            f"Admin on {self.goal} from lure foothold (expensive trap)",
            [p_access(self.goal, "user"), p_env(f"p_{self.goal}_lure2")],
            admin_from_lure_cost, [e_access(self.goal, "admin")]))
        self.lure_cost = lure_user_cost + admin_from_lure_cost

    # -- shortcut: bỏ qua 1 host, ít bước hơn nhưng đắt hơn (RQ1/RQ2) --------
    def _build_shortcuts(self) -> None:
        for src, mid, dst in self.shortcut_pairs:
            bypass = (self.scan_cost[mid] + self.exploit_cost[mid]
                      + self.scan_cost[dst] + self.exploit_cost[dst])
            sc = self._rc(SCAN_COST_RANGE)
            xc = bypass + self.rng.randint(2, 6)  # đảm bảo đắt hơn tuyến 2-hop bị bỏ qua
            self.actions.append(make_action(
                f"scan_{dst}_from_{src}", f"Scan {dst} from {src} (shortcut)",
                [p_access(src, "user"), p_reach(src, dst)],
                sc, [e_learn(f"k_{dst}")]))  # cùng fact với scan thường -> cạnh song song
            self.actions.append(make_action(
                f"exploit_{dst}_from_{src}", f"User on {dst} via {src} (shortcut, expensive)",
                [p_access(src, "user"), p_reach(src, dst),
                 p_known(f"k_{dst}"), p_env(f"p_{dst}")],
                xc, [e_access(dst, "user")]))

    # -- decoy: fact độc lập, mỗi cái nhân |V| ~×2 (điều khiển size mịn) -------
    def _build_decoys(self) -> None:
        if self.cfg.decoys <= 0:
            return
        anchor = self.path[1] if len(self.path) > 1 else self.goal  # cạnh entry->anchor luôn có
        for j in range(self.cfg.decoys):
            self.actions.append(make_action(
                f"decoy_{j}", f"Learn independent decoy fact {j} (doubles |V|)",
                [p_access(self.entry, "user"), p_reach(self.entry, anchor)],
                self._rc(SCAN_COST_RANGE), [e_learn(f"k_decoy_{j}")]))

    # -- cạnh ngược: LUÔN no-op (plan §7.2); kiểm thử loại no-op, không tạo cycle -----
    def _build_cycles(self) -> None:
        if not self.cfg.cycles:
            return
        # FIX: với shortcut (src, mid, dst), 'dst' có thể đạt được mà KHÔNG qua 'mid'
        # => return_{mid}_from_{dst} nâng quyền thật (không phải no-op). Bỏ cặp này để
        # giữ đúng bất biến "return_* LUÔN no-op" (mục đích test loại no-op cho RQ4).
        unsafe = {(mid, dst) for _, mid, dst in self.shortcut_pairs}
        for a, b in zip(self.path, self.path[1:]):
            if (a, b) in unsafe:
                continue
            self.actions.append(make_action(
                f"return_{a}_from_{b}", f"Return to {a} from {b} (back edge, luôn no-op)",
                [p_access(b, "user"), p_reach(b, a)],
                RETURN_COST, [e_access(a, "user")]))

    # -- dead-end: đi được nhưng không dẫn tới đích -----------------------
    def _build_deadends(self) -> None:
        for d in self.dead:
            parent = self.dead_parent[d]
            self.actions.append(make_action(
                f"scan_{d}", f"Scan {d} (dead-end)",
                [p_access(parent, "user"), p_reach(parent, d)],
                self._rc(SCAN_COST_RANGE), [e_learn(f"k_{d}")]))
            self.actions.append(make_action(
                f"exploit_{d}", f"User on {d} via {parent} (dead-end)",
                [p_access(parent, "user"), p_reach(parent, d),
                 p_known(f"k_{d}"), p_env(f"p_{d}")],
                self._rc(DEADEND_EXPLOIT_RANGE), [e_access(d, "user")]))
            self.env_facts.append(f"p_{d}")

    # -- kiểm tra schema theo plan §5.2, §6 -------------------------------
    def _validate(self, sc: Dict[str, Any]) -> None:
        host_ids = [h["id"] for h in sc["hosts"]]
        hs = set(host_ids)
        if len(hs) != len(host_ids):
            raise ScenarioError("Host id bị trùng.")

        access = sc["initial_state"]["access"]
        if set(access) != hs:
            raise ScenarioError("initial_state.access phải liệt kê đúng toàn bộ host (không thiếu, không thừa).")
        if any(v not in LEVELS for v in access.values()):
            raise ScenarioError("initial_state.access có level không hợp lệ.")

        edges = {tuple(e) for e in sc["topology"]}
        for a, b in edges:
            if a not in hs or b not in hs:
                raise ScenarioError(f"Topology tham chiếu host không tồn tại: {a}->{b}")

        action_ids = [a["id"] for a in sc["actions"]]
        if len(set(action_ids)) != len(action_ids):
            raise ScenarioError("Action id bị trùng.")
        if len(set(sc["env_facts"])) != len(sc["env_facts"]):
            raise ScenarioError("env_facts bị trùng.")

        env = set(sc["env_facts"])
        learned = {e["fact"] for a in sc["actions"] for e in a["effects"] if e["type"] == "learn"}
        for a in sc["actions"]:
            if not isinstance(a["cost"], int) or a["cost"] < 0:
                raise ScenarioError(f"{a['id']}: cost phải là số nguyên >= 0.")
            for p in a["preconditions"]:
                t = p["type"]
                if t == "reachable" and (p["from"], p["to"]) not in edges:
                    raise ScenarioError(f"{a['id']}: thiếu cạnh có hướng {p['from']}->{p['to']} trong topology.")
                if t == "access_at_least" and (p["host"] not in hs or p["level"] not in LEVELS):
                    raise ScenarioError(f"{a['id']}: access_at_least không hợp lệ.")
                if t == "env_fact" and p["fact"] not in env:
                    raise ScenarioError(f"{a['id']}: env_fact {p['fact']} chưa khai báo.")
                if t == PRECOND_KNOWN and p["fact"] not in learned:
                    raise ScenarioError(f"{a['id']}: fact {p['fact']} không action nào learn.")
            for e in a["effects"]:
                if e["type"] == "set_access" and (e["host"] not in hs or e["level"] not in LEVELS):
                    raise ScenarioError(f"{a['id']}: set_access không hợp lệ.")

        if sc["goal"]["host"] not in hs:
            raise ScenarioError("Goal tham chiếu host không tồn tại.")
        if self.cfg.kind == "standard" and not (self.direct_cost or 0) > (self.cheap_cost or 0):
            raise ScenarioError("Tradeoff sai: tuyến trực tiếp không đắt hơn tuyến dài.")

    # -- API chính --------------------------------------------------------
    def build(self) -> Dict[str, Any]:
        self._build_topology()
        self._build_cheap_route()
        self._build_direct_route()
        self._build_greedy_trap()
        self._build_shortcuts()
        self._build_decoys()
        self._build_deadends()
        self._build_cycles()
        if self.cfg.shuffle_actions:  # RQ1: DFS/Greedy nhạy với thứ tự action (plan §10)
            self.rng.shuffle(self.actions)

        hosts = []
        for i, hid in enumerate(self.all_ids, start=1):
            hosts.append({
                "id": hid, "ip": f"10.0.{(i - 1) // 250}.{(i - 1) % 250 + 1}",
                "hostname": "ws" if hid == self.entry else f"srv-{hid.lower()}",
                "os": "sim-os", "services": [],
            })

        access = {hid: "none" for hid in self.all_ids}
        access[self.entry] = "user"
        if self.cfg.kind == "initial-goal":
            access[self.goal] = "admin"

        scenario = {
            "scenario_id": self.cfg.scenario_id,
            "description": self._describe(),
            "hosts": hosts,
            "topology": self.topology,
            "env_facts": self.env_facts,
            "initial_state": {"access": access, "known": []},
            "actions": self.actions,
            "goal": p_access(self.goal, "admin"),
        }
        self._validate(scenario)
        return scenario

    def _describe(self) -> str:
        c = self.cfg
        text = (f"Generated ({c.kind}): {c.hosts} base hosts ({len(self.chain)} chain hop(s)), "
                f"{c.deadends} dead-end(s), {c.decoys} decoy(s), {c.shortcuts} shortcut(s)")
        if c.greedy_trap:
            text += ", greedy-trap"
        if c.cycles:
            text += ", back edges (no-op)"
        if self.cheap_cost is not None and self.direct_cost is not None:
            text += f". Long route to {self.goal} costs {self.cheap_cost}; direct route costs {self.direct_cost}"
            if self.lure_cost is not None:
                text += f"; greedy lure route costs {self.lure_cost}"
            text += "."
        elif c.kind == "unreachable":
            text += f". Goal {self.goal} has no incoming edge and no admin action: unreachable."
        else:
            text += f". Initial state already satisfies goal on {self.goal}."
        return text


# ----------------------------------------------------------------------------
# Bộ sinh kịch bản (mô hình cvss / PA-C) - dạng nguồn, bám lab-01
# ----------------------------------------------------------------------------
def _norm_role(token: Any) -> Optional[str]:
    return ROLE_ALIASES.get(str(token).strip().lower().replace(" ", "-"))


def load_cve_catalog(path: str) -> Dict[str, List[str]]:
    """Nạp scenarios/cve_catalog.json và nhóm CVE theo vai trò tấn công (plan §9.3).

    Chấp nhận 3 dạng: list bản ghi, {"cves": [...]}, hoặc map {cve_id: record}.
    Vai trò lấy từ field 'role'/'roles'/'category'/'tags'/'attack_role' (có alias).
    Generator chỉ cần ID + vai trò; VECTOR CVSS do `recost` đọc từ chính catalog này.
    """
    p = Path(path)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScenarioError(f"Không đọc được CVE catalog '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"CVE catalog '{path}' không phải JSON hợp lệ: {exc}") from exc

    if isinstance(raw, dict) and "cves" in raw:
        items = raw["cves"]
    elif isinstance(raw, dict):
        items = [{**(v if isinstance(v, dict) else {}), "id": k} for k, v in raw.items()]
    elif isinstance(raw, list):
        items = raw
    else:
        raise ScenarioError('CVE catalog không nhận dạng được (cần list, {"cves":[...]}, hoặc map id->record).')

    groups: Dict[str, List[str]] = {r: [] for r in CANON_ROLES}
    for it in items:
        if not isinstance(it, dict):
            continue
        cid = it.get("id") or it.get("cve") or it.get("cve_id")
        if not cid or not CVE_RE.match(str(cid)):
            continue
        roles = set()
        for key in ("role", "roles", "category", "categories", "tags", "attack_role"):
            val = it.get(key)
            if val is None:
                continue
            for t in (val if isinstance(val, list) else [val]):
                c = _norm_role(t)
                if c:
                    roles.add(c)
        for c in roles:
            if cid not in groups[c]:
                groups[c].append(cid)
    for c in groups:
        groups[c] = sorted(groups[c])  # plan §9.3: trong một vai trò, sắp theo CVE id tăng dần
    return groups


class CvssScenarioBuilder:
    """Sinh kịch bản dạng NGUỒN CVSS (không 'cost'), bám cấu trúc lab-01 và quy tắc plan §9.3.

    entry (user) -> entry-server (initial access CVE) -> pivot(s) (lateral CVE) -> goal (domain CVE).
    Nếu có CVE privesc: thêm tuyến privesc trên entry-server + pivot admin thẳng tới goal (ít hop hơn).
    KHÔNG áp đặt bất biến chi phí: đánh đổi L≠C (nếu có) do cấu trúc + recost quyết định (plan §9.3).
    Mọi exploit/privesc mang 'cve'; chi phí do `python -m aapef recost` tính sau.
    """

    def __init__(self, config: ScenarioConfig, catalog: Dict[str, List[str]]) -> None:
        config.validate()
        self.cfg = config
        self.rng = random.Random(config.seed)
        self.catalog = catalog

        ids = [host_label(i) for i in range(config.hosts + config.deadends)]
        self.entry = ids[0]
        self.pivots: List[str] = ids[1 : config.hosts - 1]
        self.goal = ids[config.hosts - 1]
        self.dead: List[str] = ids[config.hosts :]
        self.all_ids = ids
        self.path = [self.entry, *self.pivots]
        self.entry_server = self.pivots[0]  # luôn tồn tại vì hosts >= 3
        self.goal_reachable = config.kind != "unreachable"
        self.use_privesc = (self.goal_reachable and config.kind == "standard"
                            and len(self.pivots) >= 2
                            and bool(catalog.get(ROLE_PRIVESC)) and bool(catalog.get(ROLE_DOMAIN)))

        self.topology: List[List[str]] = []
        self.env_facts: List[str] = []
        self.actions: List[Dict[str, Any]] = []
        self.dead_parent: Dict[str, str] = {}
        # để main() in tương thích (không có chi phí ở dạng nguồn)
        self.cheap_cost = self.direct_cost = self.lure_cost = None

    # -- helpers --
    @staticmethod
    def _tail(cve: str) -> str:
        return cve.replace("CVE-", "").replace("-", "_")

    def _vuln_fact(self, host: str, cve: str) -> str:
        return f"vuln_{host}_{self._tail(cve)}"

    def _env(self, fact: str) -> str:
        if fact not in self.env_facts:
            self.env_facts.append(fact)
        return fact

    def _cves(self, role: str) -> List[str]:
        lst = self.catalog.get(role) or []
        if not lst:
            raise ScenarioError(
                f"CVE catalog '{self.cfg.cve_catalog}' thiếu vai trò '{role}' (cần cho --cost-model cvss). "
                f"Mỗi CVE cần field vai trò (role/roles/tags) ánh xạ về {CANON_ROLES}.")
        return lst

    # -- build steps --
    def _build_topology(self) -> None:
        hops = list(zip(self.path, self.path[1:]))
        self.topology = [[a, b] for a, b in hops]
        if self.goal_reachable:
            self.topology.append([self.path[-1], self.goal])
            if self.use_privesc:
                self.topology.append([self.entry_server, self.goal])
        for d in self.dead:
            parent = self.rng.choice(self.path)
            self.dead_parent[d] = parent
            self.topology.append([parent, d])
        if self.cfg.cycles:
            # Back-edge CHỈ trên path (entry..pivot cuối); mọi pivot chỉ tới được qua tiền nhiệm
            # (không có shortcut giữa pivot) => return_* luôn no-op. An toàn.
            self.topology.extend([b, a] for a, b in hops)

    def _build_entry_access(self) -> None:
        h = self.entry_server
        self.actions.append(make_learn_action(
            f"discover_{h}", f"Discover services on {h} from {self.entry}",
            [p_access(self.entry, "user"), p_reach(self.entry, h)], [e_learn(f"k_{h}")]))
        for cve in self._cves(ROLE_INITIAL):
            fact = self._vuln_fact(h, cve)
            self.actions.append(make_cve_action(
                f"exploit_{h}_{self._tail(cve)}", f"Initial access to {h} ({cve})", cve,
                [p_access(self.entry, "user"), p_reach(self.entry, h),
                 p_known(f"k_{h}"), p_env(self._env(fact))],
                [e_access(h, "user")]))

    def _build_privesc_shortcut(self) -> None:
        if not self.use_privesc:
            return
        h = self.entry_server
        for cve in self._cves(ROLE_PRIVESC):
            fact = self._vuln_fact(h, cve)
            self.actions.append(make_cve_action(
                f"privesc_{h}_{self._tail(cve)}", f"Local privilege escalation on {h} ({cve})", cve,
                [p_access(h, "user"), p_env(self._env(fact))], [e_access(h, "admin")]))
        self.actions.append(make_learn_action(
            f"discover_{self.goal}_from_{h}", f"Discover {self.goal} from {h} (admin pivot)",
            [p_access(h, "admin"), p_reach(h, self.goal)], [e_learn(f"k_{self.goal}")]))
        for cve in self._cves(ROLE_DOMAIN):
            fact = self._vuln_fact(self.goal, cve)
            self.actions.append(make_cve_action(
                f"exploit_{self.goal}_from_{h}_{self._tail(cve)}",
                f"Domain takeover on {self.goal} from {h} ({cve})", cve,
                [p_access(h, "admin"), p_reach(h, self.goal),
                 p_known(f"k_{self.goal}"), p_env(self._env(fact))],
                [e_access(self.goal, "admin")]))

    def _build_lateral_chain(self) -> None:
        for cur, nxt in zip(self.pivots, self.pivots[1:]):  # CHỈ giữa các pivot
            self.actions.append(make_learn_action(
                f"discover_{nxt}_from_{cur}", f"Discover {nxt} from {cur}",
                [p_access(cur, "user"), p_reach(cur, nxt)], [e_learn(f"k_{nxt}")]))
            for cve in self._cves(ROLE_LATERAL):
                fact = self._vuln_fact(nxt, cve)
                self.actions.append(make_cve_action(
                    f"exploit_{nxt}_from_{cur}_{self._tail(cve)}",
                    f"Lateral movement to {nxt} from {cur} ({cve})", cve,
                    [p_access(cur, "user"), p_reach(cur, nxt),
                     p_known(f"k_{nxt}"), p_env(self._env(fact))],
                    [e_access(nxt, "user")]))
        if self.goal_reachable:
            last = self.path[-1]
            self.actions.append(make_learn_action(
                f"discover_{self.goal}_from_{last}", f"Discover {self.goal} from {last}",
                [p_access(last, "user"), p_reach(last, self.goal)], [e_learn(f"k_{self.goal}")]))
            for cve in self._cves(ROLE_DOMAIN):
                fact = self._vuln_fact(self.goal, cve)
                self.actions.append(make_cve_action(
                    f"exploit_{self.goal}_from_{last}_{self._tail(cve)}",
                    f"Domain takeover on {self.goal} from {last} ({cve})", cve,
                    [p_access(last, "user"), p_reach(last, self.goal),
                     p_known(f"k_{self.goal}"), p_env(self._env(fact))],
                    [e_access(self.goal, "admin")]))

    def _build_deadends(self) -> None:
        for d in self.dead:
            parent = self.dead_parent[d]
            cve = self._cves(ROLE_LATERAL)[0]
            fact = self._vuln_fact(d, cve)
            self.actions.append(make_learn_action(
                f"discover_{d}", f"Discover dead-end {d} from {parent}",
                [p_access(parent, "user"), p_reach(parent, d)], [e_learn(f"k_{d}")]))
            self.actions.append(make_cve_action(
                f"exploit_{d}", f"User on dead-end {d} via {parent} ({cve})", cve,
                [p_access(parent, "user"), p_reach(parent, d),
                 p_known(f"k_{d}"), p_env(self._env(fact))],
                [e_access(d, "user")]))

    def _build_decoys(self) -> None:
        for j in range(self.cfg.decoys):
            self.actions.append(make_learn_action(
                f"decoy_{j}", f"Independent decoy fact {j} (doubles |V|)",
                [p_access(self.entry, "user"), p_reach(self.entry, self.entry_server)],
                [e_learn(f"k_decoy_{j}")]))

    def _build_cycles(self) -> None:
        if not self.cfg.cycles:
            return
        for a, b in zip(self.path, self.path[1:]):
            self.actions.append(make_learn_action(
                f"return_{a}_from_{b}", f"Return to {a} from {b} (back edge, luôn no-op)",
                [p_access(b, "user"), p_reach(b, a)], [e_access(a, "user")]))

    def _validate_cvss(self, sc: Dict[str, Any]) -> None:
        host_ids = [h["id"] for h in sc["hosts"]]
        hs = set(host_ids)
        if len(hs) != len(host_ids):
            raise ScenarioError("Host id bị trùng.")
        access = sc["initial_state"]["access"]
        if set(access) != hs:
            raise ScenarioError("initial_state.access phải liệt kê đúng toàn bộ host.")
        if any(v not in LEVELS for v in access.values()):
            raise ScenarioError("initial_state.access có level không hợp lệ.")
        edges = {tuple(e) for e in sc["topology"]}
        for a, b in edges:
            if a not in hs or b not in hs:
                raise ScenarioError(f"Topology tham chiếu host không tồn tại: {a}->{b}")
        action_ids = [a["id"] for a in sc["actions"]]
        if len(set(action_ids)) != len(action_ids):
            raise ScenarioError("Action id bị trùng.")
        if len(set(sc["env_facts"])) != len(sc["env_facts"]):
            raise ScenarioError("env_facts bị trùng.")
        env = set(sc["env_facts"])
        learned = {e["fact"] for a in sc["actions"] for e in a["effects"] if e["type"] == "learn"}
        for a in sc["actions"]:
            if "cost" in a:
                raise ScenarioError(f"{a['id']}: kịch bản nguồn cvss KHÔNG được mang 'cost' (recost sẽ tính).")
            sets_access = any(e["type"] == "set_access" for e in a["effects"])
            is_exploit = sets_access and not a["id"].startswith("return_")
            has_cve = "cve" in a
            if is_exploit and not has_cve:
                raise ScenarioError(f"{a['id']}: action exploit/privesc phải có 'cve'.")
            if has_cve:
                if not is_exploit:
                    raise ScenarioError(f"{a['id']}: chỉ action exploit/privesc mới gắn 'cve'.")
                if not CVE_RE.match(str(a["cve"])):
                    raise ScenarioError(f"{a['id']}: cve '{a['cve']}' sai định dạng CVE-YYYY-NNNN.")
                if "cvss_override" in a:
                    raise ScenarioError(f"{a['id']}: không dùng 'cve' cùng 'cvss_override'.")
            for p in a["preconditions"]:
                t = p["type"]
                if t == "reachable" and (p["from"], p["to"]) not in edges:
                    raise ScenarioError(f"{a['id']}: thiếu cạnh {p['from']}->{p['to']} trong topology.")
                if t == "access_at_least" and (p["host"] not in hs or p["level"] not in LEVELS):
                    raise ScenarioError(f"{a['id']}: access_at_least không hợp lệ.")
                if t == "env_fact" and p["fact"] not in env:
                    raise ScenarioError(f"{a['id']}: env_fact {p['fact']} chưa khai báo.")
                if t == PRECOND_KNOWN and p["fact"] not in learned:
                    raise ScenarioError(f"{a['id']}: fact {p['fact']} không action nào learn.")
            for e in a["effects"]:
                if e["type"] == "set_access" and (e["host"] not in hs or e["level"] not in LEVELS):
                    raise ScenarioError(f"{a['id']}: set_access không hợp lệ.")
        if sc["goal"]["host"] not in hs:
            raise ScenarioError("Goal tham chiếu host không tồn tại.")

    def _describe(self) -> str:
        used = {r: self.catalog.get(r, []) for r in (ROLE_INITIAL, ROLE_LATERAL, ROLE_PRIVESC, ROLE_DOMAIN)}
        parts = [f"Generated CVSS source ({self.cfg.kind}): {self.cfg.hosts} base hosts "
                 f"(entry {self.entry} -> ... -> goal {self.goal}), "
                 f"{self.cfg.deadends} dead-end(s), {self.cfg.decoys} decoy(s)"]
        if self.use_privesc:
            parts.append(f"privesc shortcut on {self.entry_server}")
        if self.cfg.cycles:
            parts.append("back edges (no-op)")
        text = ", ".join(parts) + ". No cost fields (source form): run `python -m aapef recost`. "
        text += "CVEs by role: " + "; ".join(f"{r}=[{','.join(v)}]" for r, v in used.items() if v) + "."
        return text

    def build(self) -> Dict[str, Any]:
        self._build_topology()
        self._build_entry_access()
        self._build_privesc_shortcut()
        self._build_lateral_chain()
        self._build_deadends()
        self._build_decoys()
        self._build_cycles()
        if self.cfg.shuffle_actions:
            self.rng.shuffle(self.actions)

        hosts = []
        for i, hid in enumerate(self.all_ids, start=1):
            hosts.append({
                "id": hid, "ip": f"10.0.{(i - 1) // 250}.{(i - 1) % 250 + 1}",
                "hostname": "ws" if hid == self.entry else f"srv-{hid.lower()}",
                "os": "sim-os", "services": [],
            })
        access = {hid: "none" for hid in self.all_ids}
        access[self.entry] = "user"
        if self.cfg.kind == "initial-goal":
            access[self.goal] = "admin"

        scenario = {
            "scenario_id": self.cfg.scenario_id,
            "description": self._describe(),
            "hosts": hosts,
            "topology": self.topology,
            "env_facts": self.env_facts,
            "initial_state": {"access": access, "known": []},
            "actions": self.actions,
            "goal": p_access(self.goal, "admin"),
        }
        self._validate_cvss(scenario)
        return scenario


# ----------------------------------------------------------------------------
# Bộ phân tích tham chiếu (oracle độc lập, bám plan §7, §10, §12.5)
#   - successors: action applicable VÀ làm đổi state (no-op bị loại), set_access chỉ nâng.
#   - state = (tuple access theo thứ tự host, frozenset known) ~ state_key chuẩn hoá.
# ----------------------------------------------------------------------------
class Action(NamedTuple):
    id: str
    cost: int
    acc_req: Tuple[Tuple[int, int], ...]
    known_req: Tuple[str, ...]
    acc_eff: Tuple[Tuple[int, int], ...]
    learn: Tuple[str, ...]


class Model(NamedTuple):
    actions: Tuple[Action, ...]
    start: Tuple[Tuple[int, ...], frozenset]
    goal_i: int
    goal_lv: int


class Ref(NamedTuple):
    status: str  # "optimal" | "unreachable" | "limit"
    cost: int
    length: int
    plan: Tuple[str, ...]


def compile_model(sc: Dict[str, Any]) -> Model:
    index = {h["id"]: i for i, h in enumerate(sc["hosts"])}
    edges = {tuple(e) for e in sc["topology"]}  # có hướng
    env = set(sc["env_facts"])
    actions: List[Action] = []
    for a in sc["actions"]:
        acc_req, known_req, static_ok = [], [], True
        for p in a["preconditions"]:
            t = p["type"]
            if t == "access_at_least":
                acc_req.append((index[p["host"]], LEVELS[p["level"]]))
            elif t == PRECOND_KNOWN:
                known_req.append(p["fact"])
            elif t == "env_fact":
                static_ok = static_ok and p["fact"] in env
            elif t == "reachable":
                static_ok = static_ok and (p["from"], p["to"]) in edges
            else:
                raise ScenarioError(f"Loại precondition không hỗ trợ: {t}")
        if not static_ok:
            continue  # precondition tĩnh sai -> action không bao giờ applicable
        acc_eff, learn = [], []
        for e in a["effects"]:
            if e["type"] == "set_access":
                acc_eff.append((index[e["host"]], LEVELS[e["level"]]))
            elif e["type"] == "learn":
                learn.append(e["fact"])
            else:
                raise ScenarioError(f"Loại effect không hỗ trợ: {e['type']}")
        actions.append(Action(a["id"], a.get("cost", 0), tuple(acc_req), tuple(known_req),
                              tuple(acc_eff), tuple(learn)))
    init = sc["initial_state"]
    access0 = tuple(LEVELS[init["access"][h["id"]]] for h in sc["hosts"])
    goal = sc["goal"]
    return Model(tuple(actions), (access0, frozenset(init["known"])),
                 index[goal["host"]], LEVELS[goal["level"]])


def _successors(actions, state):
    access, known = state
    for a in actions:
        if any(access[i] < lv for i, lv in a.acc_req):
            continue
        if any(f not in known for f in a.known_req):
            continue
        acc = list(access)
        for i, lv in a.acc_eff:
            if lv > acc[i]:
                acc[i] = lv
        nxt = (tuple(acc), known.union(a.learn))
        if nxt == state:  # no-op: không phải cạnh (plan §7.2)
            continue
        yield a, nxt


def _relevant_actions(model: Model) -> List[Action]:
    """Phân tích ngược: chỉ giữ action có thể góp phần tới goal (không đổi chi phí tối ưu)."""
    need = {("a", model.goal_i)}
    chosen: Dict[int, Action] = {}
    changed = True
    while changed:
        changed = False
        for idx, a in enumerate(model.actions):
            if idx in chosen:
                continue
            produced = {("a", i) for i, _ in a.acc_eff} | {("k", f) for f in a.learn}
            if produced & need:
                chosen[idx] = a
                changed = True
                need.update(("a", i) for i, _ in a.acc_req)
                need.update(("k", f) for f in a.known_req)
    return [chosen[i] for i in sorted(chosen)]


def reference_search(model: Model, objective: str, max_states: int) -> Ref:
    """Dijkstra tối ưu theo 'cost' (C*) hoặc 'length' (L*, hoà thì chọn cost nhỏ nhất)."""
    actions = _relevant_actions(model)

    def is_goal(state) -> bool:
        return state[0][model.goal_i] >= model.goal_lv

    if is_goal(model.start):
        return Ref("optimal", 0, 0, ())

    def prio(c: int, l: int) -> Tuple[int, int]:
        return (c, l) if objective == "cost" else (l, c)

    best = {model.start: prio(0, 0)}
    heap = [(prio(0, 0), 0, 0, 0, model.start, ())]
    tick = 1
    while heap:
        p, _, c0, l0, state, plan = heapq.heappop(heap)
        if p > best[state]:
            continue
        if is_goal(state):
            return Ref("optimal", c0, l0, plan)
        if len(best) > max_states:
            return Ref("limit", 0, 0, ())
        for a, nxt in _successors(actions, state):
            c, l = c0 + a.cost, l0 + 1
            np_ = prio(c, l)
            if nxt not in best or np_ < best[nxt]:
                best[nxt] = np_
                heapq.heappush(heap, (np_, tick, c, l, nxt, plan + (a.id,)))
                tick += 1
    return Ref("unreachable", 0, 0, ())


def reference_greedy(model: Model, max_states: int) -> Ref:
    """Mô phỏng Greedy Best-First với heuristic plan §10 (số mức access còn thiếu trên goal).

    Dùng TOÀN BỘ action (không prune) để phản ánh đúng việc heuristic có thể dẫn Greedy sai.
    Tie-break theo thứ tự chèn (counter) - tất định. Đây là oracle xác nhận bẫy, không thay
    thế engine thật, nhưng đủ để chứng minh scenario khiến Greedy chọn tuyến không tối ưu.
    """
    def h(state) -> int:
        return max(0, model.goal_lv - state[0][model.goal_i])

    start = model.start
    if h(start) == 0:
        return Ref("optimal", 0, 0, ())
    counter = 0
    heap = [(h(start), counter, 0, 0, start, ())]
    visited = set()
    while heap:
        _, _, c0, l0, state, plan = heapq.heappop(heap)
        if state in visited:
            continue
        visited.add(state)
        if h(state) == 0:
            return Ref("optimal", c0, l0, plan)  # path Greedy TÌM RA (không nhất thiết tối ưu)
        if len(visited) > max_states:
            return Ref("limit", 0, 0, ())
        for a, nxt in _successors(model.actions, state):
            if nxt in visited:
                continue
            counter += 1
            heapq.heappush(heap, (h(nxt), counter, c0 + a.cost, l0 + 1, nxt, plan + (a.id,)))
    return Ref("unreachable", 0, 0, ())


def measure_state_space(model: Model, max_states: int) -> Dict[str, Any]:
    """|V|, |E| theo plan §12.5: duyệt toàn bộ reachable, mỗi cạnh-theo-action đếm riêng."""
    visited = {model.start}
    queue = deque([model.start])
    edges = 0
    capped = False
    while queue:
        state = queue.popleft()
        for _, nxt in _successors(model.actions, state):
            edges += 1  # gồm cả cạnh tới state đã visited
            if nxt not in visited:
                if len(visited) >= max_states:
                    capped = True
                    continue
                visited.add(nxt)
                queue.append(nxt)
    return {"V": len(visited), "E": edges, "capped": capped}


def verify(scenario: Dict[str, Any], builder: ScenarioBuilder, max_states: int) -> Dict[str, Any]:
    """Kiểm tra kịch bản config đúng ý đồ thiết kế cho RQ; trả về các giá trị tham chiếu."""
    model = compile_model(scenario)
    by_cost = reference_search(model, "cost", max_states)
    by_length = reference_search(model, "length", max_states)
    if "limit" in (by_cost.status, by_length.status):
        raise ScenarioError(f"Verify vượt giới hạn {max_states} trạng thái; tăng --max-states.")

    kind = builder.cfg.kind
    if kind == "unreachable":
        if by_cost.status != "unreachable":
            raise ScenarioError("Verify thất bại: kịch bản 'unreachable' lại có đường tới goal.")
        return {"kind": kind}
    if by_cost.status != "optimal":
        raise ScenarioError("Verify thất bại: goal không đạt được.")
    if kind == "initial-goal":
        if by_cost.cost != 0 or by_cost.plan:
            raise ScenarioError("Verify thất bại: initial-goal phải cho path rỗng, cost 0.")
        return {"kind": kind, "C_star": 0, "L_star": 0}

    if by_cost.cost != builder.cheap_cost:
        raise ScenarioError(f"Verify thất bại: C* = {by_cost.cost}, kỳ vọng {builder.cheap_cost}.")
    if f"admin_{builder.goal}_direct" in by_cost.plan:
        raise ScenarioError("Verify thất bại: tuyến tối ưu theo cost lại dùng tuyến trực tiếp.")
    if not (by_length.length < by_cost.length and by_length.cost > by_cost.cost):
        raise ScenarioError("Verify thất bại: không có tradeoff L/C (RQ1/RQ2 sẽ không phân biệt được).")

    result: Dict[str, Any] = {
        "kind": kind,
        "C_star": by_cost.cost, "L_of_C_opt": by_cost.length,
        "L_star": by_length.length, "C_of_L_opt": by_length.cost,
        "C_gap_min": by_length.cost - by_cost.cost,   # cận dưới độ lệch C của BFS (RQ1)
        "L_gap": by_cost.length - by_length.length,   # độ lệch L của Dijkstra (RQ2)
        "plan_C_opt": list(by_cost.plan),
    }

    greedy = reference_greedy(model, max_states)
    if greedy.status == "optimal":
        result["greedy_C"] = greedy.cost
        result["greedy_L"] = greedy.length
        result["greedy_gap"] = greedy.cost - by_cost.cost
        result["greedy_plan"] = list(greedy.plan)

    if builder.cfg.greedy_trap:
        lured = (greedy.status == "optimal"
                 and greedy.cost > by_cost.cost
                 and any("lure" in a for a in greedy.plan))
        if not lured:
            raise ScenarioError(
                "Greedy trap không hiệu lực: heuristic không dẫn Greedy vào tuyến đắt "
                f"(greedy C={greedy.cost}, C*={by_cost.cost}, plan={list(greedy.plan)}).")
    return result


def verify_cvss(scenario: Dict[str, Any], builder: CvssScenarioBuilder, max_states: int) -> Dict[str, Any]:
    """Kiểm tra kịch bản cvss dạng nguồn: reachability + L* + biên. KHÔNG assert tradeoff chi phí
    (chi phí chưa tồn tại trước recost; plan §9.3: không ép kết quả)."""
    model = compile_model(scenario)
    by_len = reference_search(model, "length", max_states)
    if by_len.status == "limit":
        raise ScenarioError(f"Verify vượt giới hạn {max_states} trạng thái; tăng --max-states.")
    kind = builder.cfg.kind
    if kind == "unreachable":
        if by_len.status != "unreachable":
            raise ScenarioError("Verify thất bại: kịch bản 'unreachable' lại có đường tới goal.")
        return {"kind": kind, "cost_model": "cvss"}
    if by_len.status != "optimal":
        raise ScenarioError("Verify thất bại: goal không đạt được.")
    if kind == "initial-goal":
        if by_len.length != 0 or by_len.plan:
            raise ScenarioError("Verify thất bại: initial-goal phải cho path rỗng.")
        return {"kind": kind, "cost_model": "cvss", "L_star": 0}
    return {"kind": kind, "cost_model": "cvss", "L_star": by_len.length,
            "plan_L_opt": list(by_len.plan),
            "note": "C* chưa xác định (source form). Recost rồi --verify bản trong scenarios/cvss/."}


# ----------------------------------------------------------------------------
# Tự dò --target-v (fix: điều khiển |V| mịn hơn, theo mục tiêu) - chỉ mô hình config
# ----------------------------------------------------------------------------
def tune_target_v(cfg: ScenarioConfig, target: int, max_states: int) -> Tuple[int, int, int, bool]:
    """Dò (deadends, decoys) để |V| gần target nhất.

    |V| tăng theo cấp nhân (dead-end ~×3, decoy ~×2) nên KHÔNG đảm bảo trúng chính xác:
    chọn cấu hình có |V| đo thực gần target nhất, ưu tiên |V| >= target, rồi ít knob hơn.
    Trả về (deadends, decoys, |V| đạt được, capped).
    """
    if target < 1:
        raise ScenarioError("--target-v phải >= 1.")
    best: Optional[Tuple[Tuple[int, int, int], int, int, int, bool]] = None
    for de in range(TUNE_MAX_DEADENDS + 1):
        row_min: Optional[int] = None
        for dc in range(TUNE_MAX_DECOYS + 1):
            trial = replace(cfg, deadends=de, decoys=dc)
            try:
                sc = ScenarioBuilder(trial).build()
            except ScenarioError:
                continue
            space = measure_state_space(compile_model(sc), max_states)
            v = space["V"]
            key = (0 if v >= target else 1, abs(v - target), de + dc)
            if best is None or key < best[0]:
                best = (key, de, dc, v, space["capped"])
            row_min = v if row_min is None else min(row_min, v)
            if v >= target * 3:  # overshoot: thôi tăng decoys cho de này
                break
        if row_min is not None and row_min >= target * 3:
            break  # ngay cả decoys=0 đã vượt xa -> thôi tăng deadends
    if best is None:
        raise ScenarioError("Không dò được cấu hình cho --target-v.")
    return best[1], best[2], best[3], best[4]


# ----------------------------------------------------------------------------
# Ghi file & CLI
# ----------------------------------------------------------------------------
def write_json(data: Dict[str, Any], out_path: Path) -> None:
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except OSError as exc:
        raise ScenarioError(f"Không thể ghi file '{out_path}': {exc}") from exc


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Sinh kịch bản JSON cho AAPEF (State Planning & Cost Optimization).")
    p.add_argument("--id", dest="scenario_id", default=DEFAULT_ID, help=f"ID kịch bản (mặc định: {DEFAULT_ID})")
    p.add_argument("--hosts", type=int, default=MIN_HOSTS,
                   help=f"Số host cơ bản, không gồm dead-end, tối thiểu {MIN_HOSTS} (mặc định: {MIN_HOSTS})")
    p.add_argument("--deadends", type=int, default=1, help="Số host nhánh cụt, nhân |V| ~×3 (mặc định: 1)")
    p.add_argument("--decoys", type=int, default=0,
                   help="Số fact decoy độc lập, mỗi cái nhân |V| ~×2 (điều khiển size mịn; mặc định: 0)")
    p.add_argument("--target-v", type=int, default=None,
                   help="Tự dò (deadends, decoys) để |V| gần mục tiêu này; ghi đè --deadends/--decoys (chỉ config)")
    p.add_argument("--out", default=None, help=f"File JSON đầu ra (mặc định: {DEFAULT_OUT_DIR}/<id>.json)")
    p.add_argument("--seed", type=int, default=42, help="Seed để tái lập (ảnh hưởng cả cost ở config; mặc định: 42)")
    p.add_argument("--shortcuts", type=int, default=0,
                   help="Số shortcut bỏ qua 1 host (ít bước hơn, đắt hơn); tối đa hosts-3; chỉ config (mặc định: 0)")
    p.add_argument("--cycles", action="store_true",
                   help="Thêm back-edge topology + action return_* (LUÔN no-op; không tạo cycle state-space)")
    p.add_argument("--greedy-trap", action="store_true",
                   help="Thêm tuyến lure khớp heuristic Greedy để dẫn Greedy vào tuyến đắt (chỉ config, kind standard)")
    p.add_argument("--kind", choices=KINDS, default="standard",
                   help="standard | unreachable (goal không đạt được) | initial-goal (initial_state đã đạt goal)")
    p.add_argument("--shuffle-actions", action="store_true", help="Xáo thứ tự action theo seed (độ nhạy DFS/Greedy)")
    p.add_argument("--cost-model", choices=COST_MODELS, default="config",
                   help="config (chi phí gõ tay/seed, hồi quy) | cvss (nguồn CVE, không cost; recost tính sau)")
    p.add_argument("--cve-catalog", default=DEFAULT_CVE_CATALOG,
                   help=f"Đường dẫn CVE catalog cho --cost-model cvss (mặc định: {DEFAULT_CVE_CATALOG})")
    p.add_argument("--verify", action="store_true",
                   help="Giải thử bằng oracle: config -> C*, L*, tradeoff, greedy-trap; cvss -> reachability, L*")
    p.add_argument("--stats", action="store_true",
                   help="Đo |V|,|E| theo plan §12.5 và ghi <out>.meta.json kèm giá trị tham chiếu")
    p.add_argument("--max-states", type=int, default=DEFAULT_MAX_STATES,
                   help=f"Giới hạn số trạng thái cho --verify/--stats/--target-v (mặc định: {DEFAULT_MAX_STATES})")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    ref: Optional[Dict[str, Any]] = None
    space: Optional[Dict[str, Any]] = None
    target_info: Optional[Dict[str, Any]] = None
    try:
        cfg = ScenarioConfig(
            scenario_id=args.scenario_id, hosts=args.hosts, deadends=args.deadends,
            seed=args.seed, shortcuts=args.shortcuts, cycles=args.cycles, kind=args.kind,
            shuffle_actions=args.shuffle_actions, decoys=args.decoys, greedy_trap=args.greedy_trap,
            cost_model=args.cost_model, cve_catalog=args.cve_catalog)
        cfg.validate()

        if args.target_v is not None:
            if cfg.cost_model == "cvss":
                raise ScenarioError("--target-v hiện chỉ hỗ trợ --cost-model config.")
            de, dc, achieved_v, capped = tune_target_v(cfg, args.target_v, args.max_states)
            cfg = replace(cfg, deadends=de, decoys=dc)
            target_info = {"target_V": args.target_v, "achieved_V": achieved_v,
                           "deadends": de, "decoys": dc, "capped": capped}

        if cfg.cost_model == "cvss":
            catalog = load_cve_catalog(cfg.cve_catalog)
            builder = CvssScenarioBuilder(cfg, catalog)
            scenario = builder.build()
            if args.verify or args.stats:
                ref = verify_cvss(scenario, builder, args.max_states)
        else:
            builder = ScenarioBuilder(cfg)
            scenario = builder.build()
            if args.verify or args.stats:
                ref = verify(scenario, builder, args.max_states)
        if args.stats:
            space = measure_state_space(compile_model(scenario), args.max_states)
        out = Path(args.out) if args.out else Path(DEFAULT_OUT_DIR) / f"{cfg.scenario_id}.json"
        write_json(scenario, out)
        if args.stats:
            write_json({"scenario_id": cfg.scenario_id, "params": asdict(cfg),
                        "target": target_info, "reference": ref, "state_space": space},
                       out.with_suffix(".meta.json"))
    except ScenarioError as exc:
        print(f"[LỖI] {exc}", file=sys.stderr)
        return 1

    print(f"[OK] Đã xuất kịch bản '{cfg.scenario_id}' ({cfg.kind}, cost-model={cfg.cost_model}) -> {out}")
    print(f"     Hosts: {len(scenario['hosts'])} | Actions: {len(scenario['actions'])} | "
          f"Dead-ends: {cfg.deadends} | Decoys: {cfg.decoys} | Shortcuts: {cfg.shortcuts}"
          f"{' | Greedy-trap' if cfg.greedy_trap else ''}")
    if builder.cheap_cost is not None:
        line = f"     Tuyến dài (rẻ): {builder.cheap_cost} | Tuyến trực tiếp (đắt): {builder.direct_cost}"
        if builder.lure_cost is not None:
            line += f" | Tuyến lure (bẫy Greedy): {builder.lure_cost}"
        print(line)
    if target_info is not None:
        mark = ">=" if target_info["capped"] else "="
        print(f"     [TARGET-V] mục tiêu {target_info['target_V']} -> |V| {mark} {target_info['achieved_V']} "
              f"(deadends={target_info['deadends']}, decoys={target_info['decoys']})")
    if ref is not None:
        if ref.get("cost_model") == "cvss":
            if "L_star" in ref:
                print(f"     [VERIFY OK] cvss source | L* = {ref['L_star']} | C* chưa tính (chạy `recost`)")
            else:
                print(f"     [VERIFY OK] cvss source | kind={ref['kind']}")
        elif "C_gap_min" in ref:
            print(f"     [VERIFY OK] C* = {ref['C_star']} (L={ref['L_of_C_opt']}) | "
                  f"L* = {ref['L_star']} (C={ref['C_of_L_opt']}) | "
                  f"độ lệch: C >= +{ref['C_gap_min']}, L = +{ref['L_gap']}")
            if "greedy_C" in ref:
                print(f"     [GREEDY] C(greedy) = {ref['greedy_C']} (L={ref['greedy_L']}), "
                      f"lệch so với C*: +{ref['greedy_gap']}")
        else:
            print(f"     [VERIFY OK] kind={ref['kind']}")
    if space is not None:
        mark = ">=" if space["capped"] else "="
        print(f"     [STATS] |V| {mark} {space['V']}, |E| {mark} {space['E']}"
              f"{' (chạm --max-states)' if space['capped'] else ''} -> {out.with_suffix('.meta.json')}")
    if cfg.cost_model == "cvss":
        print("     [CVSS] Dạng nguồn (không cost). Chạy `python -m aapef recost` để sinh bản benchmark scenarios/cvss/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())