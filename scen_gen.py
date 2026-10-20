#!/usr/bin/env python3
"""scenario_generator.py - Sinh kịch bản JSON cho AAPEF (State Planning & Cost Optimization).

Schema bám theo large-01.json và AAPEF Master Plan v0.4 (§5-§7, §12).

Cấu trúc kịch bản (mọi kịch bản "standard"):
  * Host A            : điểm xuất phát (access = user).
  * Chuỗi trung gian  : B, C, ... (hosts - 2 host) -> tuyến DÀI nhưng RẺ.
  * Host đích         : host cuối của nhóm host cơ bản (cần admin).
  * Dead-end hosts    : nằm sau nhóm cơ bản, có scan + exploit nhưng không dẫn tới đích.
  * Tuyến trực tiếp   : A -> đích, NGẮN nhưng cost RẤT CAO.
  * Greedy lure (tùy) : tuyến đưa goal lên 'user' rồi 'admin' rất đắt, khớp heuristic Greedy.

Chi phí action:
  Mọi cost được LẤY NGẪU NHIÊN theo --seed trong các khoảng cấu hình bên dưới, nên đổi seed
  là đổi "địa hình chi phí". Các bất biến cần cho RQ được GIỮ bằng cách suy ra, không cố định:
    - direct  > tổng tuyến rẻ (C_cheap)      -> tradeoff RQ1/RQ2.
    - shortcut > chi phí hai hop bị bỏ qua   -> ít bước hơn nhưng đắt hơn.
    - lure    > direct                       -> Greedy bị dẫn vào tuyến đắt nhất.

LƯU Ý về mô hình (quan trọng cho --cycles):
  Access chỉ TĂNG (set_access chỉ nâng, không hạ - plan §5.2) và known chỉ thêm. Do đó
  state-space REACHABLE luôn là một ĐỒ THỊ KHÔNG CHU TRÌNH CÓ HƯỚNG (DAG): không tồn tại
  chu trình ở mức state. --cycles KHÔNG tạo (và không thể tạo) cycle state-space; nó chỉ
  thêm back-edge trong topology host + các action return_* mà LUÔN là no-op (đặt lại quyền
  đã có). Những no-op này bị `successors` loại (plan §7.2) nên không sinh cạnh trong |V|,|E|;
  mục đích của chúng là kiểm thử việc engine loại no-op/self-loop và visited (RQ4).

Ánh xạ tính năng -> câu hỏi nghiên cứu:
  RQ1 (C lệch tối ưu)   : tuyến rẻ vs trực tiếp vs lure; --shortcuts thêm điểm trung gian L/C.
  RQ2 (L lệch tối thiểu): như RQ1, BFS chọn tuyến ít bước nhưng đắt.
  RQ3 (effort theo size): --deadends nhân |V| ~×3; --decoys nhân ~×2 (mịn hơn);
                          --target-v tự dò để |V| gần mục tiêu; --stats đo |V|,|E| (plan §12.5).
  RQ4 (robustness)      : --kind unreachable | initial-goal; --cycles (no-op / back-edge);
                          --greedy-trap (heuristic dẫn Greedy sai); --shortcuts (cạnh song song).

Ví dụ:
  python scenario_generator.py --hosts 3 --deadends 1 --verify
  python scenario_generator.py --id trap-01 --hosts 5 --greedy-trap --verify
  python scenario_generator.py --id size-01 --hosts 5 --target-v 500 --stats
  python scenario_generator.py --id medium-02 --hosts 7 --deadends 2 --shortcuts 3 --cycles --stats
  for v in 100 300 900; do python scenario_generator.py --id size-v$v --hosts 5 --target-v $v --stats; done
"""

from __future__ import annotations

import argparse
import heapq
import json
import random
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

# Khoảng chi phí: lấy ngẫu nhiên theo seed (fix: cost phụ thuộc seed).
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


# ----------------------------------------------------------------------------
# Bộ sinh kịch bản
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
        for a, b in zip(self.path, self.path[1:]):
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
        actions.append(Action(a["id"], a["cost"], tuple(acc_req), tuple(known_req),
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
    """Kiểm tra kịch bản đúng ý đồ thiết kế cho RQ; trả về các giá trị tham chiếu."""
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


# ----------------------------------------------------------------------------
# Tự dò --target-v (fix: điều khiển |V| mịn hơn, theo mục tiêu)
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
                   help="Tự dò (deadends, decoys) để |V| gần mục tiêu này; ghi đè --deadends/--decoys")
    p.add_argument("--out", default=None, help=f"File JSON đầu ra (mặc định: {DEFAULT_OUT_DIR}/<id>.json)")
    p.add_argument("--seed", type=int, default=42, help="Seed để tái lập (ảnh hưởng cả cost; mặc định: 42)")
    p.add_argument("--shortcuts", type=int, default=0,
                   help="Số shortcut bỏ qua 1 host (ít bước hơn, đắt hơn); tối đa hosts-3 (mặc định: 0)")
    p.add_argument("--cycles", action="store_true",
                   help="Thêm back-edge topology + action return_* (LUÔN no-op; không tạo cycle state-space)")
    p.add_argument("--greedy-trap", action="store_true",
                   help="Thêm tuyến lure khớp heuristic Greedy (plan §10) để dẫn Greedy vào tuyến đắt (chỉ kind standard)")
    p.add_argument("--kind", choices=KINDS, default="standard",
                   help="standard | unreachable (goal không đạt được) | initial-goal (initial_state đã đạt goal)")
    p.add_argument("--shuffle-actions", action="store_true", help="Xáo thứ tự action theo seed (độ nhạy DFS/Greedy)")
    p.add_argument("--verify", action="store_true",
                   help="Giải thử bằng oracle: xác nhận C*, L*, tradeoff, unreachable, và hiệu lực greedy-trap")
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
            shuffle_actions=args.shuffle_actions, decoys=args.decoys, greedy_trap=args.greedy_trap)
        cfg.validate()

        if args.target_v is not None:
            de, dc, achieved_v, capped = tune_target_v(cfg, args.target_v, args.max_states)
            cfg = replace(cfg, deadends=de, decoys=dc)
            target_info = {"target_V": args.target_v, "achieved_V": achieved_v,
                           "deadends": de, "decoys": dc, "capped": capped}

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

    print(f"[OK] Đã xuất kịch bản '{cfg.scenario_id}' ({cfg.kind}) -> {out}")
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
        if "C_gap_min" in ref:
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
    return 0


if __name__ == "__main__":
    sys.exit(main())