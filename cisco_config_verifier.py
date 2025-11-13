#!/usr/bin/env python3
"""
Cisco Configuration Verification Script

Validates generated Cisco configurations against testset verification requirements
using Batfish network simulation server at 192.168.31.170:9996.
"""

import os
import json
import sys
import urllib3
import requests
import ipaddress
import pandas as pd
from typing import Dict, List, Tuple
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints, PathConstraints
from datetime import datetime


class CiscoConfigVerifier:
    # ------------------------------
    # Debug helpers
    # ------------------------------
    def _answer_to_rows(self, ans):
        """Return (rows, columns) from a Batfish Answer in a robust way (with preview cap)."""
        try:
            df = ans.frame()
            # Cap to first 200 rows to keep debug files readable
            if len(df) > 200:
                df = df.head(200)
            return df.to_dict('records'), list(df.columns)
        except Exception:
            try:
                rows = ans.get("answerElements", [{}])[0].get("rows", [])
                # Cap rows for safety
                if isinstance(rows, list) and len(rows) > 200:
                    rows = rows[:200] + ["<truncated more rows>"]
                cols = list(rows[0].keys()) if rows and isinstance(rows[0], dict) else []
                return rows, cols
            except Exception:
                return [], []

    def _json_sanitize(self, obj, *, _depth=0, _max_depth=6, _max_items=1000, _max_str=20000):
        """
        Recursively coerce Batfish/Pandas objects into JSON-serializable primitives.
        - Limits depth to avoid cycles.
        - Truncates huge lists/dicts/strings for safety.
        """
        if _depth > _max_depth:
            return f"<depth_limit({_max_depth})>"
        # Primitives
        if obj is None or isinstance(obj, (bool, int, float)):
            return obj
        if isinstance(obj, str):
            return obj if len(obj) <= _max_str else (obj[:_max_str] + f"...<truncated {len(obj) - _max_str} chars>")
        # numpy scalar
        try:
            import numpy as _np  # optional
            if isinstance(obj, (_np.generic,)):
                return obj.item()
        except Exception:
            pass
        # bytes/bytearray → str
        if isinstance(obj, (bytes, bytearray)):
            s = obj.decode(errors="replace")
            return s if len(s) <= _max_str else (s[:_max_str] + f"...<truncated {len(s) - _max_str} chars>")
        # dict
        if isinstance(obj, dict):
            out = {}
            items = list(obj.items())
            for i, (k, v) in enumerate(items[:_max_items]):
                out[str(k)] = self._json_sanitize(v, _depth=_depth + 1, _max_depth=_max_depth, _max_items=_max_items,
                                                  _max_str=_max_str)
            if len(items) > _max_items:
                out["__truncated__"] = f"{len(items) - _max_items} more items truncated"
            return out
        # list/tuple/set
        if isinstance(obj, (list, tuple, set)):
            seq = list(obj)
            trimmed = seq[:_max_items]
            out = [self._json_sanitize(x, _depth=_depth + 1, _max_depth=_max_depth, _max_items=_max_items,
                                       _max_str=_max_str) for x in trimmed]
            if len(seq) > _max_items:
                out.append(f"<truncated {len(seq) - _max_items} more items>")
            return out
        # Fallback → str
        try:
            s = str(obj)
        except Exception:
            s = repr(obj)
        return s if len(s) <= _max_str else (s[:_max_str] + f"...<truncated {len(s) - _max_str} chars>")

    def _dump_debug(self, base_dir: str, testset_id: int, config_type: str,
                    task_index: int, task_type: str, debug_obj: dict) -> str:
        """
        Write debug JSON atomically to avoid partial files.
        Returns the final filepath or "" on failure.
        """
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            debug_dir = os.path.join(base_dir, f"{testset_id}_cisco", f"debug_{config_type.lower()}")
            os.makedirs(debug_dir, exist_ok=True)
            fname = f"{task_index:02d}_{task_type}_{ts}.json"
            fpath = os.path.join(debug_dir, fname)
            tmp_path = fpath + ".tmp"

            safe_obj = self._json_sanitize(debug_obj)

            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(safe_obj, f, ensure_ascii=False, indent=2, default=str)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.replace(tmp_path, fpath)
            except Exception:
                import shutil as _shutil
                _shutil.move(tmp_path, fpath)
            return fpath
        except Exception as e:
            try:
                fallback = {
                    "error": f"debug_dump_failed: {e}",
                    "task_type": task_type,
                    "note": "original debug object not serializable; stored stringified snapshot",
                    "snapshot": (str(debug_obj)[:4000] + ("...<truncated>" if len(str(debug_obj)) > 4000 else ""))
                }
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                debug_dir = os.path.join(base_dir, f"{testset_id}_cisco", f"debug_{config_type.lower()}")
                os.makedirs(debug_dir, exist_ok=True)
                fname = f"{task_index:02d}_{task_type}_{ts}_fallback.json"
                fpath = os.path.join(debug_dir, fname)
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(fallback, f, ensure_ascii=False, indent=2)
                return fpath
            except Exception:
                return ""

    def __init__(self, batfish_host: str = "192.168.31.170", batfish_port: int = 9996):
        """Initialize the verifier with Batfish server connection."""
        self.batfish_host = batfish_host
        self.batfish_port = batfish_port

        # Disable proxy and SSL warnings
        os.environ['NO_PROXY'] = batfish_host
        os.environ['no_proxy'] = batfish_host
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Create requests session without proxy
        session = requests.Session()
        session.proxies = {}

        try:
            self.bf = Session(host=batfish_host, port=batfish_port)
            print(f"✓ Connected to Batfish server at {batfish_host}:{batfish_port}")
        except Exception as e:
            print(f"✗ Failed to connect to Batfish server at {batfish_host}:{batfish_port}")
            print(f"  Error: {e}")
            sys.exit(1)

    def load_testset(self, testset_path: str) -> Dict:
        """Load a testset JSON file."""
        with open(testset_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def load_snapshot(self, snapshot_path: str, network_name: str, snapshot_name: str):
        """Load a configuration snapshot into Batfish."""
        self.bf.set_network(network_name)
        self.bf.init_snapshot(snapshot_path, name=snapshot_name, overwrite=True)

    def check_bgp_session_status(self, node: str = None) -> Tuple[bool, str, dict]:
        """
        Check BGP session status.
        Returns: (success, message, debug_dict)
        """
        debug = {"question": "bgpSessionStatus", "node": node}
        try:
            ans = self.bf.q.bgpSessionStatus().answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            bgp_sessions = ans.frame()

            if bgp_sessions.empty:
                return False, "No BGP sessions found", debug

            # Filter by node if specified
            if node:
                _node = str(node).split('[', 1)[0].strip().lower()
                bgp_sessions = bgp_sessions.assign(__node_base=bgp_sessions['Node'].astype(str).str.split('[', n=1, expand=False).str[0].str.strip().str.lower())
                bgp_sessions = bgp_sessions[bgp_sessions['__node_base'] == _node]

            # Check if all sessions are ESTABLISHED
            established_sessions = bgp_sessions[bgp_sessions['Established_Status'] == 'ESTABLISHED']
            total_sessions = len(bgp_sessions)
            established_count = len(established_sessions)

            debug["filtered_rows"] = self._json_sanitize(bgp_sessions.to_dict('records'))
            debug["total_sessions"] = total_sessions
            debug["established_count"] = established_count

            if established_count == total_sessions:
                return True, f"All {total_sessions} BGP session(s) are ESTABLISHED", debug
            else:
                failed_sessions = bgp_sessions[bgp_sessions['Established_Status'] != 'ESTABLISHED']
                details = failed_sessions[['Node', 'Remote_Node', 'Established_Status']].to_dict('records')
                debug["failed_sessions"] = self._json_sanitize(details)
                return False, f"Only {established_count}/{total_sessions} BGP sessions ESTABLISHED. Failed: {details}", debug

        except Exception as e:
            return False, f"Error checking BGP sessions: {str(e)}", debug

    def check_ospf_neighbors(self, node: str = None) -> Tuple[bool, str, dict]:
        """
        Check OSPF neighbor relationships (robust across schema variants).
        Returns: (success, message, debug_dict)
        """
        debug = {"question": "ospfEdges", "node": node}
        try:
            ans = self.bf.q.ospfEdges().answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            try:
                df = ans.frame()
            except Exception:
                rows = ans.get("answerElements", [{}])[0].get("rows", [])
                import pandas as _pd
                df = _pd.DataFrame(rows)

            if df is None or df.empty:
                return False, "No OSPF adjacencies found", debug

            cols = {c.lower(): c for c in df.columns}
            node_col = next((cols[k] for k in cols if k == 'node' or k.endswith('.node')), None)
            rnode_col = next((cols[k] for k in cols if 'remote' in k and 'node' in k), None)

            if node is None:
                # Count all adjacencies
                debug["total_adjacencies"] = len(df)
                return True, f"Found {len(df)} OSPF neighbor relationship(s)", debug

            target = str(node).split('[', 1)[0].strip().lower()
            count = 0
            if node_col and rnode_col:
                _df = df.assign(
                    __node_base=df[node_col].astype(str).str.split('[', n=1, expand=False).str[0].str.strip().str.lower(),
                    __remote_base=df[rnode_col].astype(str).str.split('[', n=1, expand=False).str[0].str.strip().str.lower()
                )
                count = ((_df['__node_base'] == target) | (_df['__remote_base'] == target)).sum()
                debug["filtered_rows"] = self._json_sanitize(_df[(_df['__node_base'] == target) | (_df['__remote_base'] == target)].to_dict('records'))
            else:
                iface_col = cols.get('interface', 'Interface')
                rif_col = cols.get('remote_interface', 'Remote_Interface')
                if iface_col not in df.columns or rif_col not in df.columns:
                    return False, "OSPF edges missing Interface columns", debug
                matched_rows = []
                for _, r in df.iterrows():
                    a_node, _ = self._parse_ifstr(r.get(iface_col, ''))
                    b_node, _ = self._parse_ifstr(r.get(rif_col, ''))
                    if a_node == target or b_node == target:
                        count += 1
                        matched_rows.append(self._json_sanitize(r.to_dict()))
                debug["filtered_rows"] = matched_rows

            debug["neighbor_count"] = count
            return True, f"Found {count} OSPF neighbor relationship(s) for {node}", debug
        except Exception as e:
            return False, f"Error checking OSPF neighbors: {str(e)}", debug

    # ------------------------------
    # New granular verification APIs
    # ------------------------------
    def check_bgp_session_between(self, a_node: str, b_node: str, expect: str = "ESTABLISHED") -> Tuple[bool, str, dict]:
        """Verify BGP session state between two nodes. Returns (success, message, debug_dict)"""
        debug = {"question": "bgpSessionStatus"}
        try:
            ans = self.bf.q.bgpSessionStatus().answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            df = None
            try:
                df = ans.frame()
            except Exception:
                import pandas as _pd
                df = _pd.DataFrame(rows)

            if df is None or df.empty:
                return False, "No BGP sessions found", debug

            # Normalize column names
            cols_map = {c.lower(): c for c in df.columns}
            node_col = cols_map.get('node', 'Node')
            remote_col = cols_map.get('remote_node', 'Remote_Node')
            status_col = cols_map.get('established_status', 'Established_Status')

            # Normalize hostnames to ignore VRF suffixes like 'R1[vrf default]'
            def _base(n):
                return str(n).split('[', 1)[0].strip().lower()
            a_base, b_base = _base(a_node), _base(b_node)
            df = df.assign(
                __node_base=df[node_col].apply(_base),
                __remote_base=df[remote_col].apply(_base),
            )
            mask = ((df['__node_base'] == a_base) & (df['__remote_base'] == b_base)) | \
                   ((df['__node_base'] == b_base) & (df['__remote_base'] == a_base))
            rel = df[mask]

            debug["filtered_rows"] = self._json_sanitize(rel.to_dict('records'))

            if rel.empty:
                return False, f"No BGP session rows between {a_node} and {b_node}", debug

            ok = (rel[status_col].astype(str).str.upper() == expect.upper()).all()
            if ok:
                return True, f"BGP session {a_node}↔{b_node} is {expect}", debug
            else:
                bad = rel[rel[status_col].astype(str).str.upper() != expect.upper()]
                details = bad[[node_col, remote_col, status_col]].to_dict('records')
                return False, f"BGP session not {expect}: {details}", debug
        except Exception as e:
            return False, f"Error checking BGP session between {a_node} and {b_node}: {e}", debug

    def check_bgp_rib_contains(self, node: str, prefix: str) -> Tuple[bool, str, dict]:
        """Verify node's BGP RIB has the specific prefix. Returns (success, message, debug_dict)"""
        debug = {"question": "routes(protocols=bgp)", "node": node, "prefix": prefix}
        try:
            ans = self.bf.q.routes(nodes=node, protocols="bgp").answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            import pandas as _pd
            df = None
            try:
                df = ans.frame()
            except Exception:
                df = _pd.DataFrame(rows)

            if df is None or df.empty:
                return False, f"No BGP routes on {node}", debug

            cols_map = {c.lower(): c for c in df.columns}
            net_col = cols_map.get('network', 'Network')

            want = ipaddress.ip_network(prefix, strict=False)
            def match(p):
                try:
                    return ipaddress.ip_network(p, strict=False) == want
                except Exception:
                    return False

            matched = df[net_col].astype(str).apply(match).any()
            debug["matched"] = bool(matched)

            if matched:
                return True, f"{node} BGP RIB contains {prefix}", debug
            return False, f"{node} BGP RIB does not contain {prefix}", debug
        except Exception as e:
            return False, f"Error checking BGP RIB on {node}: {e}", debug

    def check_bgp_advertised_contains(self, node: str, prefix: str) -> Tuple[bool, str, dict]:
        """Verify node advertises the prefix to any peer. Fallback if bgpAdvertisements is unavailable."""
        debug = {"question": "bgpAdvertisements", "node": node, "prefix": prefix}
        try:
            # Primary path: use bgpAdvertisements if available
            try:
                ans = self.bf.q.bgpAdvertisements(nodes=node).answer()
                rows, cols = self._answer_to_rows(ans)
                debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

                try:
                    df = ans.frame()
                except Exception:
                    rows = ans.get("answerElements", [{}])[0].get("rows", [])
                    df = pd.DataFrame(rows)

                if df is None or df.empty:
                    return False, f"No BGP advertisements found for {node}", debug

                cols = {c.lower(): c for c in df.columns}
                type_col = next((cols[k] for k in cols if 'type' == k or k.endswith('.type')), None)
                net_col = next((cols[k] for k in cols if k == 'network' or k.endswith('.network')), None)

                if not type_col or not net_col:
                    # Unexpected schema → fallback path
                    raise AttributeError("bgpAdvertisements schema unsupported")

                sent = df[df[type_col].astype(str).str.upper().str.contains('SENT', na=False)]
                debug["sent_rows"] = self._json_sanitize(sent.to_dict('records'))

                if sent.empty:
                    return False, f"{node} has no SENT BGP advertisements", debug

                want = str(ipaddress.ip_network(prefix, strict=False))

                def match(p):
                    try:
                        return str(ipaddress.ip_network(str(p), strict=False)) == want
                    except Exception:
                        return False

                matched = sent[net_col].apply(match).any()
                debug["matched"] = bool(matched)

                if matched:
                    return True, f"{node} advertises {prefix}", debug
                return False, f"{node} does not advertise {prefix}", debug

            except AttributeError:
                # Fallback: 无 bgpAdvertisements 的环境
                # 近似判断：节点的 BGP RIB 有该前缀 + 存在至少一个 ESTABLISHED 会话
                debug["fallback_mode"] = True
                rib_ok, _, rib_debug = self.check_bgp_rib_contains(node, prefix)
                sess_ok, _, sess_debug = self.check_bgp_session_status(node)
                debug["rib_check"] = rib_debug
                debug["session_check"] = sess_debug
                if rib_ok and sess_ok:
                    return True, f"{node} likely advertises {prefix} (fallback: RIB+session)", debug
                elif not sess_ok:
                    return False, f"{node} has no established BGP sessions (fallback)", debug
                else:
                    return False, f"{node} BGP RIB lacks {prefix} (fallback)", debug
        except Exception as e:
            return False, f"Error checking advertised routes on {node}: {e}", debug

    def check_bgp_received_only(self, node: str, allowed_prefixes: List[str]) -> Tuple[bool, str, dict]:
        """Verify node only receives allowed prefixes from peers.
        Primary: use bgpAdvertisements(Type=RECEIVED).
        Fallback (no bgpAdvertisements): compare node's BGP RIB against allowed set (best-effort).
        """
        debug = {"question": "bgpAdvertisements_received", "node": node, "allowed_prefixes": allowed_prefixes}
        try:
            # -------- Primary path: use bgpAdvertisements if available --------
            try:
                ans = self.bf.q.bgpAdvertisements(nodes=node).answer()
                rows, cols = self._answer_to_rows(ans)
                debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

                try:
                    df = ans.frame()
                except Exception:
                    rows = ans.get("answerElements", [{}])[0].get("rows", [])
                    df = pd.DataFrame(rows)

                if df is None or df.empty:
                    # If nothing received, treat as pass for 'only' constraint
                    return True, f"{node} received no BGP routes (treated as compliant)", debug

                cols = {c.lower(): c for c in df.columns}
                type_col = next((cols[k] for k in cols if 'type' == k or k.endswith('.type')), None)
                net_col  = next((cols[k] for k in cols if k == 'network' or k.endswith('.network')), None)

                if not type_col or not net_col:
                    # Schema unexpected: fall back
                    raise AttributeError("bgpAdvertisements schema unsupported")

                rec = df[df[type_col].astype(str).str.upper().str.contains('RECEIVED', na=False)]
                debug["received_rows"] = self._json_sanitize(rec.to_dict('records'))

                if rec.empty:
                    return True, f"{node} received no BGP routes (treated as compliant)", debug

                allowed = {str(ipaddress.ip_network(p, strict=False)) for p in allowed_prefixes}

                def norm(p):
                    try:
                        return str(ipaddress.ip_network(str(p), strict=False))
                    except Exception:
                        return None

                seen = {norm(p) for p in rec[net_col].tolist()}
                seen.discard(None)
                debug["seen_prefixes"] = sorted(list(seen))
                debug["allowed_prefixes_normalized"] = sorted(list(allowed))

                if seen.issubset(allowed):
                    return True, f"{node} only received allowed prefixes: {sorted(seen)}", debug
                else:
                    extra = sorted(list(seen - allowed))
                    debug["unexpected_prefixes"] = extra
                    return False, f"{node} received unexpected prefixes: {extra}", debug

            except AttributeError:
                # -------- Fallback path: no bgpAdvertisements available --------
                # Best-effort: compare the node's BGP RIB against allowed set.
                debug["fallback_mode"] = True
                ans = self.bf.q.routes(nodes=node, protocols="bgp").answer()
                rows, cols = self._answer_to_rows(ans)
                debug.update({"fallback_raw_rows": self._json_sanitize(rows), "fallback_columns": self._json_sanitize(cols)})

                try:
                    rib = ans.frame()
                except Exception:
                    rows = ans.get("answerElements", [{}])[0].get("rows", [])
                    rib = pd.DataFrame(rows)

                if rib is None or rib.empty:
                    # No BGP routes observed on the node — treat as compliant (nothing to violate)
                    return True, f"{node} has no BGP routes (fallback: treated as compliant)", debug

                cols = {c.lower(): c for c in rib.columns}
                net_col = cols.get('network') or next((c for c in rib.columns if 'network' in c.lower()), None)
                if not net_col:
                    return False, "BGP RIB missing Network column (fallback)", debug

                allowed = {str(ipaddress.ip_network(p, strict=False)) for p in allowed_prefixes}

                def norm(p):
                    try:
                        return str(ipaddress.ip_network(str(p), strict=False))
                    except Exception:
                        return None

                seen = {norm(p) for p in rib[net_col].tolist()}
                seen.discard(None)
                debug["fallback_seen_prefixes"] = sorted(list(seen))

                if seen.issubset(allowed):
                    return True, f"{node} BGP RIB ⊆ allowed prefixes (fallback): {sorted(seen)}", debug
                else:
                    extra = sorted(list(seen - allowed))
                    debug["fallback_unexpected_prefixes"] = extra
                    return False, f"{node} BGP RIB contains prefixes outside allowed set (fallback): {extra}", debug
        except Exception as e:
            return False, f"Error checking received routes on {node}: {e}", debug

    # ------------------------------
    # OSPF helpers for heterogeneous schemas
    # ------------------------------
    def _parse_ifstr(self, ifstr: str):
        """
        Parse strings like 'r1[GigabitEthernet0/0/0]' into (node_base_lower, interface).
        If parsing fails, return (str(ifstr).lower(), None).
        """
        try:
            s = str(ifstr)
            if '[' in s and s.endswith(']'):
                node, rest = s.split('[', 1)
                iface = rest[:-1]
                return node.strip().split('[', 1)[0].strip().lower(), iface.strip()
            return s.strip().split('[', 1)[0].strip().lower(), None
        except Exception:
            return str(ifstr).strip().lower(), None

    def _ospf_iface_area_df(self):
        """
        Return a DataFrame of OSPF interface configuration with columns:
        __node_base (lower, no VRF suffix), Interface, Area
        Robust to schema variations (missing Node, different column names).
        """
        try:
            ans = self.bf.q.ospfInterfaceConfiguration().answer()
        except Exception:
            return None

        # Build a DataFrame robustly
        try:
            df = ans.frame()
        except Exception:
            rows = ans.get("answerElements", [{}])[0].get("rows", [])
            import pandas as _pd
            df = _pd.DataFrame(rows)

        if df is None or df.empty:
            return None

        # Flexible column discovery
        cols_lc = {c.lower(): c for c in df.columns}

        def find_col(sub):
            for c in df.columns:
                if sub in c.lower():
                    return c
            return None

        node_col = cols_lc.get('node') or find_col('node') or find_col('hostname')
        iface_col = cols_lc.get('interface') or find_col('interface')
        area_col = cols_lc.get('area') or find_col('area')

        if iface_col is None or area_col is None:
            # 没有接口或 area 列就没法判断
            return None

        import pandas as _pd
        work = df.copy()

        # 若没有 Node 列，则从 Interface 像 'r1[Gi0/0/0]' 解析节点名
        if node_col is None:
            def _parse_node(val):
                s = str(val)
                if '[' in s and s.endswith(']'):
                    return s.split('[', 1)[0].strip()
                return s.strip()

            work['Node'] = work[iface_col].apply(_parse_node)
        else:
            work = work.rename(columns={node_col: 'Node'})

        # 统一列名
        if iface_col != 'Interface':
            work = work.rename(columns={iface_col: 'Interface'})
        if area_col != 'Area':
            work = work.rename(columns={area_col: 'Area'})

        # 生成 __node_base（小写、去掉 [vrf ...] 等后缀）
        work = work.assign(
            __node_base=work['Node'].astype(str).str.split('[', n=1, expand=False).str[0].str.strip().str.lower()
        )
        return work[['__node_base', 'Interface', 'Area']]

    def check_ospf_area_contains(self, area: str, nodes: List[str]) -> Tuple[bool, str, dict]:
        """Verify all nodes participate in the specified OSPF area (via ospfInterfaceConfiguration). Returns (success, message, debug_dict)"""
        debug = {"question": "ospfInterfaceConfiguration", "area": area, "nodes": nodes}
        try:
            df = self._ospf_iface_area_df()
            if df is None or df.empty:
                return False, "No OSPF interface configuration found", debug
            # Normalize targets
            target_nodes = [str(n).split('[', 1)[0].strip().lower() for n in nodes]
            # Select rows matching area (string compare)
            sub = df[df['Area'].astype(str) == str(area)]
            present = set(sub['__node_base'].astype(str))
            debug["raw_rows"] = self._json_sanitize(sub.to_dict('records'))
            missing = [n for n in target_nodes if n not in present]
            if not missing:
                return True, f"All nodes present in OSPF area {area}", debug
            else:
                return False, f"Nodes missing in area {area}: {missing}", debug
        except Exception as e:
            return False, f"Error checking OSPF area {area}: {e}", debug

    def check_ospf_neighbor_count(self, node: str, expect: int) -> Tuple[bool, str, dict]:
        """Verify OSPF neighbor count for a node. Works even when ospfEdges lacks Area/Node columns."""
        debug = {"question": "ospfEdges_neighbor_count", "node": node, "expect": expect}
        try:
            ans = self.bf.q.ospfEdges().answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            try:
                df = ans.frame()
            except Exception:
                rows = ans.get("answerElements", [{}])[0].get("rows", [])
                import pandas as _pd
                df = _pd.DataFrame(rows)

            if df is None or df.empty:
                return False, "No OSPF adjacencies found", debug

            cols = {c.lower(): c for c in df.columns}
            node_col = next((cols[k] for k in cols if k == 'node' or k.endswith('.node')), None)
            rnode_col = next((cols[k] for k in cols if 'remote' in k and 'node' in k), None)

            target = str(node).split('[', 1)[0].strip().lower()
            neighbors = set()

            if node_col and rnode_col:
                # Simple path if columns exist
                _df = df.copy()
                _df = _df.assign(
                    __node_base=_df[node_col].astype(str).str.split('[', n=1, expand=False).str[0].str.strip().str.lower(),
                    __remote_base=_df[rnode_col].astype(str).str.split('[', n=1, expand=False).str[0].str.strip().str.lower(),
                )
                mask = (_df['__node_base'] == target) | (_df['__remote_base'] == target)
                _df = _df[mask]
                debug["filtered_rows"] = self._json_sanitize(_df.to_dict('records'))
                for _, r in _df.iterrows():
                    a = r['__node_base']; b = r['__remote_base']
                    if a == target and b != target:
                        neighbors.add(b)
                    if b == target and a != target:
                        neighbors.add(a)
            else:
                # Fallback: parse Interface / Remote_Interface
                iface_col = cols.get('interface', 'Interface')
                rif_col = cols.get('remote_interface', 'Remote_Interface')
                if iface_col not in df.columns or rif_col not in df.columns:
                    return False, "OSPF edges missing Interface columns", debug
                matched_rows = []
                for _, r in df.iterrows():
                    a_node, _ = self._parse_ifstr(r.get(iface_col, ''))
                    b_node, _ = self._parse_ifstr(r.get(rif_col, ''))
                    if a_node == target and b_node:
                        neighbors.add(b_node)
                        matched_rows.append(self._json_sanitize(r.to_dict()))
                    elif b_node == target and a_node:
                        neighbors.add(a_node)
                        matched_rows.append(self._json_sanitize(r.to_dict()))
                debug["filtered_rows"] = matched_rows

            cnt = len(neighbors)
            debug["neighbor_count"] = cnt
            debug["neighbors"] = sorted(list(neighbors))

            if cnt == expect:
                return True, f"{node} has {cnt} OSPF neighbors (expected {expect})", debug
            else:
                return False, f"{node} has {cnt} OSPF neighbors (expected {expect})", debug
        except Exception as e:
            return False, f"Error checking OSPF neighbor count on {node}: {e}", debug
    def check_ospf_lsa_summary_present(self, from_area: str, to_area: str, node: str = None) -> Tuple[bool, str, dict]:
        """
        Heuristic: consider summary presence if we see any OSPF inter-area (IA) routes in the network.
        Optionally filter by a given node.
        """
        debug = {"question": "routes_ospf_ia", "from_area": from_area, "to_area": to_area, "node": node}
        try:
            ans = self.bf.q.routes(nodes=node).answer() if node else self.bf.q.routes().answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            try:
                df = ans.frame()
            except Exception:
                rows = ans.get("answerElements", [{}])[0].get("rows", [])
                df = pd.DataFrame(rows)

            if df is None or df.empty:
                return False, "No routes available for OSPF summary check", debug

            cols = {c.lower(): c for c in df.columns}
            proto_col = next((cols[k] for k in cols if k == 'protocol' or k.endswith('.protocol')), None)
            if not proto_col:
                return False, "Routes table missing Protocol column", debug

            ia_mask = df[proto_col].astype(str).str.upper().str.contains("OSPF_IA", na=False)
            debug["ospf_ia_routes"] = self._json_sanitize(df[ia_mask].to_dict('records'))

            has_ia = ia_mask.any()
            if has_ia:
                return True, "Inter-area (OSPF_IA) routes present (summary likely)", debug
            else:
                return False, "No OSPF_IA routes seen (summary not evident)", debug
        except Exception as e:
            return False, f"Error checking OSPF summary LSA: {e}", debug

    def check_no_ospf_external_on_border(self, area: str) -> Tuple[bool, str, dict]:
        """
        Heuristic: ensure no OSPF external routes (E1/E2) exist in the network (coarse check).
        """
        debug = {"question": "routes_ospf_external", "area": area}
        try:
            ans = self.bf.q.routes().answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            try:
                df = ans.frame()
            except Exception:
                rows = ans.get("answerElements", [{}])[0].get("rows", [])
                df = pd.DataFrame(rows)

            if df is None or df.empty:
                return True, "No routes found; treat as compliant", debug

            cols = {c.lower(): c for c in df.columns}
            proto_col = next((cols[k] for k in cols if k == 'protocol' or k.endswith('.protocol')), None)
            if not proto_col:
                return True, "Protocol column not found; skipping external route check", debug

            ext_mask = df[proto_col].astype(str).str.upper().str.contains("OSPF_E1|OSPF_E2", na=False)
            debug["external_routes"] = self._json_sanitize(df[ext_mask].to_dict('records'))

            has_external = ext_mask.any()
            if has_external:
                return False, "External OSPF routes (E1/E2) found in network", debug
            return True, "No external OSPF routes (E1/E2) detected", debug
        except Exception as e:
            return False, f"Error checking OSPF external leakage: {e}", debug

    def check_ospf_nssa_present(self, area: str) -> Tuple[bool, str, dict]:
        """Verify NSSA area existence (best-effort via OSPF area configuration)."""
        debug = {"question": "ospfAreaConfiguration", "area": area}
        try:
            ans = self.bf.q.ospfAreaConfiguration().answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            df = ans.frame()
            if df.empty:
                return False, "No OSPF area configuration found", debug

            cols = {c.lower(): c for c in df.columns}
            area_col = cols.get('area', 'Area')
            type_col = cols.get('area_type', 'Area_Type')

            sub = df[df[area_col].astype(str) == str(area)]
            debug["area_config"] = self._json_sanitize(sub.to_dict('records'))

            if sub.empty:
                return False, f"Area {area} not found", debug
            ok = sub[type_col].astype(str).str.upper().str.contains("NSSA", na=False).any()
            if ok:
                return True, f"Area {area} is NSSA", debug
            return False, f"Area {area} is not NSSA", debug
        except Exception as e:
            return False, f"Error checking OSPF NSSA on area {area}: {e}", debug

    def check_ospf_abr_present(self, node: str, areas: List[str]) -> Tuple[bool, str, dict]:
        """Verify node is ABR connecting the given areas (heuristic: participates in multiple areas)."""
        debug = {"question": "ospfAreaConfiguration_abr", "node": node, "areas": areas}
        try:
            ans = self.bf.q.ospfAreaConfiguration().answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            df = ans.frame()
            if df.empty:
                return False, "No OSPF area configuration found", debug

            cols = {c.lower(): c for c in df.columns}
            node_col = cols.get('node', 'Node')
            area_col = cols.get('area', 'Area')

            _node = str(node).split('[', 1)[0].strip().lower()
            df = df.assign(__node_base=df[node_col].astype(str).str.split('[', n=1, expand=False).str[0].str.strip().str.lower())
            sub = df[df['__node_base'] == _node]
            debug["node_area_config"] = self._json_sanitize(sub.to_dict('records'))

            seen = set(sub[area_col].astype(str))
            need = set(map(str, areas))
            debug["areas_seen"] = sorted(list(seen))
            debug["areas_required"] = sorted(list(need))

            if need.issubset(seen):
                return True, f"{node} participates in areas {sorted(seen)} (ABR expected)", debug
            else:
                missing = sorted(list(need - seen))
                debug["missing_areas"] = missing
                return False, f"{node} is missing areas {missing}", debug
        except Exception as e:
            return False, f"Error checking OSPF ABR on {node}: {e}", debug

    def check_no_static_route(self, node: str, prefix: str) -> Tuple[bool, str, dict]:
        """Verify node does not have a static route for the prefix."""
        debug = {"question": "routes_static", "node": node, "prefix": prefix}
        try:
            ans = self.bf.q.routes(nodes=node, protocols="static").answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            df = ans.frame()
            if df.empty:
                return True, f"No static routes on {node}", debug

            cols = {c.lower(): c for c in df.columns}
            net_col = cols.get('network', 'Network')

            want = ipaddress.ip_network(prefix, strict=False)
            def covers(p):
                try:
                    return want == ipaddress.ip_network(p, strict=False)
                except Exception:
                    return False

            matched = df[net_col].astype(str).apply(covers)
            debug["matched_routes"] = self._json_sanitize(df[matched].to_dict('records'))

            if matched.any():
                return False, f"Static route for {prefix} exists on {node}", debug
            return True, f"No static route for {prefix} on {node}", debug
        except Exception as e:
            return False, f"Error checking static routes on {node}: {e}", debug

    def check_reachability(self, src_node: str, dst_ip: str) -> Tuple[bool, str, dict]:
        """
        Check if src_node can reach dst_ip using Batfish.
        Returns: (success, message, debug_dict)
        """
        debug = {"question": "traceroute+reachability", "src": src_node, "dst": dst_ip, "traceroute": {}, "reachability": {}}
        try:
            # Normalize Batfish startLocation syntax; using '@enter(node)' is robust across versions.
            start_loc = f"@enter({src_node})"

            # -----------------------
            # Method 1: Traceroute
            # -----------------------
            try:
                traceroute = self.bf.q.traceroute(
                    startLocation=start_loc,
                    headers=HeaderConstraints(dstIps=dst_ip)
                ).answer()
                t_rows, t_cols = self._answer_to_rows(traceroute)
                debug["traceroute"] = self._json_sanitize({"rows": t_rows, "columns": t_cols})
                try:
                    result_frame = traceroute.frame()
                except Exception:
                    rows = traceroute.get("answerElements", [{}])[0].get("rows", [])
                    result_frame = pd.DataFrame(rows)

                if not result_frame.empty and 'Traces' in result_frame.columns:
                    traces_lists = result_frame['Traces'].tolist()
                    for traces in traces_lists:
                        if not traces:
                            continue
                        for t in traces:
                            # Pybatfish returns Trace objects; read disposition safely
                            try:
                                dispo = getattr(t, 'disposition', None)
                                dispo_name = getattr(dispo, 'name', str(dispo)).upper() if dispo is not None else ''
                            except Exception:
                                dispo_name = str(t).upper()

                            if 'ACCEPTED' in dispo_name or 'DELIVERED' in dispo_name:
                                return True, f"Reachability OK: {src_node} -> {dst_ip} (traceroute {dispo_name})", debug

                    # We had traces but none accepted
                    return False, f"Reachability FAILED: {src_node} cannot reach {dst_ip} (traceroute shows drops)", debug
            except Exception:
                # Ignore and continue to next method
                pass

            # -----------------------
            # Method 2: Route existence on source
            # -----------------------
            try:
                routes = self.bf.q.routes(nodes=src_node).answer().frame()

                if not routes.empty:
                    dip = ipaddress.ip_address(dst_ip)

                    for _, route in routes.iterrows():
                        network = route.get('Network', '')
                        if not network or '/' not in network:
                            continue

                        try:
                            if dip in ipaddress.ip_network(network, strict=False):
                                next_hop = route.get('Next_Hop_IP', route.get('Next_Hop', ''))
                                protocol = route.get('Protocol', '')
                                return True, f"Route present on {src_node}: {network} via {next_hop} ({protocol})", debug
                        except Exception:
                            continue
            except Exception:
                # Ignore and continue
                pass

            # -----------------------
            # Method 3: Reachability() fallback
            # -----------------------
            try:
                reach = self.bf.q.reachability(
                    pathConstraints=PathConstraints(startLocation=start_loc),
                    headers=HeaderConstraints(dstIps=dst_ip)
                ).answer()
                r_rows, r_cols = self._answer_to_rows(reach)
                debug["reachability"] = self._json_sanitize({"rows": r_rows, "columns": r_cols})
                try:
                    df = reach.frame()
                except Exception:
                    rows = reach.get("answerElements", [{}])[0].get("rows", [])
                    df = pd.DataFrame(rows)

                if df.empty:
                    return False, f"No path found from {src_node} to {dst_ip}", debug

                # Prefer explicit Disposition column if present
                if 'Disposition' in df.columns:
                    # Values are FlowDisposition enums; cast to str and look for ACCEPT
                    accepted = df['Disposition'].astype(str).str.upper().str.contains('ACCEPT', na=False)
                    if accepted.any():
                        return True, f"Reachability OK: {src_node} can reach {dst_ip} (Disposition ACCEPTED)", debug
                    else:
                        return False, f"Reachability FAILED: {src_node} cannot reach {dst_ip} (Disposition not ACCEPTED)", debug

                # Fallback: try Traces column if Disposition column is missing
                if 'Traces' in df.columns:
                    traces_lists = df['Traces'].tolist()
                    for traces in traces_lists:
                        if not traces:
                            continue
                        for t in traces:
                            dispo = getattr(t, 'disposition', None)
                            dispo_name = getattr(dispo, 'name', str(dispo)).upper() if dispo is not None else ''
                            if 'ACCEPTED' in dispo_name or 'DELIVERED' in dispo_name:
                                return True, f"Reachability OK: {src_node} can reach {dst_ip} (trace ACCEPTED)", debug

                # If none of the indicators show success
                return False, f"Reachability FAILED: {src_node} cannot reach {dst_ip}", debug
            except Exception as e3:
                return False, f"Error checking reachability: {str(e3)}", debug

        except Exception as e:
            return False, f"Error checking reachability from {src_node} to {dst_ip}: {str(e)}", debug

    def check_route_exists(self, node: str, network: str) -> Tuple[bool, str, dict]:
        """
        Check if a specific route exists in the routing table of a node (IP-equal, not string-equal).
        """
        debug = {"question": "routes", "node": node, "network": network}
        try:
            ans = self.bf.q.routes(nodes=node).answer()
            rows, cols = self._answer_to_rows(ans)
            debug.update({"raw_rows": self._json_sanitize(rows), "columns": self._json_sanitize(cols)})

            try:
                routes = ans.frame()
            except Exception:
                rows = ans.get("answerElements", [{}])[0].get("rows", [])
                routes = pd.DataFrame(rows)

            if routes is None or routes.empty:
                return False, f"No routes found on {node}", debug

            cols = {c.lower(): c for c in routes.columns}
            net_col = cols.get('network') or next((c for c in routes.columns if 'network' in c.lower()), None)
            if not net_col:
                return False, "Routes table missing Network column", debug

            try:
                want = ipaddress.ip_network(network, strict=False)
            except Exception:
                return False, f"Invalid network: {network}", debug

            def equal_net(s):
                try:
                    return ipaddress.ip_network(str(s), strict=False) == want
                except Exception:
                    return False

            matched_mask = routes[net_col].astype(str).apply(equal_net)
            debug["matched_routes"] = self._json_sanitize(routes[matched_mask].to_dict('records'))

            if matched_mask.any():
                return True, f"Route {str(want)} exists on {node}", debug
            else:
                return False, f"Route {str(want)} not found on {node}", debug
        except Exception as e:
            return False, f"Error checking routes on {node}: {str(e)}", debug

    def parse_verification_requirements(self, verification_text: str) -> List[Dict]:
        """
        Parse verification text and extract verification tasks.

        Example verification text:
        "在两端执行 show ip bgp summary，邻居状态应为 Established；从 R1 ping 192.168.20.1 可达，从 R2 ping 192.168.10.1 可达。"

        Returns list of verification tasks.
        """
        # Try to decode as JSON array of structured tasks
        try:
            parsed = json.loads(verification_text)
            if isinstance(parsed, list) and all(isinstance(t, dict) and "type" in t for t in parsed):
                return parsed
        except Exception:
            pass

        tasks = []

        # Check for BGP session verification
        if "bgp" in verification_text.lower() and "established" in verification_text.lower():
            tasks.append({
                "type": "bgp_session",
                "description": "Verify BGP sessions are ESTABLISHED"
            })

        # Check for OSPF neighbor verification
        if "ospf neighbor" in verification_text.lower():
            tasks.append({
                "type": "ospf_neighbor",
                "description": "Verify OSPF neighbor relationships"
            })

        # Check for reachability tests (ping)
        # Pattern: "从 R1 ping 192.168.20.1 可达" or "在 R1 上 ping 10.200.4.1"
        import re
        ping_patterns = [
            r'从\s*(\w+)\s*ping\s*([\d\.]+)',
            r'在\s*(\w+)\s*上?\s*ping\s*([\d\.]+)',
        ]

        for pattern in ping_patterns:
            matches = re.findall(pattern, verification_text)
            for match in matches:
                src_node, dst_ip = match
                tasks.append({
                    "type": "reachability",
                    "src_node": src_node,
                    "dst_ip": dst_ip,
                    "description": f"Verify {src_node} can ping {dst_ip}"
                })

        # Check for route visibility
        # Pattern: "在 R1 上应看到 172.16.3.0/24 路由"
        route_patterns = [
            r'在\s*(\w+)\s*上?应?看到\s*([\d\.\/]+)\s*路由',
        ]

        for pattern in route_patterns:
            matches = re.findall(pattern, verification_text)
            for match in matches:
                node, network = match
                tasks.append({
                    "type": "route_exists",
                    "node": node,
                    "network": network,
                    "description": f"Verify {network} route exists on {node}"
                })

        return tasks

    def verify_testset(self, testset_id: int, testset_dir: str, results_dir: str, use_fixed: bool = False) -> Dict:
        """
        Verify a single testset configuration.

        Args:
            testset_id: Test case ID (1-10)
            testset_dir: Directory containing testset JSON files
            results_dir: Directory containing generated configs
            use_fixed: If True, verify configs from fixed/ subdirectory

        Returns:
            Dictionary with verification results
        """
        config_type = "Fixed" if use_fixed else "Original"
        debug_base = os.path.join("cisco_verify")
        os.makedirs(debug_base, exist_ok=True)
        debug_config_type = config_type
        print(f"\n{'='*80}")
        print(f"Verifying Testset {testset_id} ({config_type})")
        print(f"{'='*80}")

        # Load testset
        testset_path = os.path.join(testset_dir, f"{testset_id}.json")
        if not os.path.exists(testset_path):
            return {
                "testset_id": testset_id,
                "status": "error",
                "message": f"Testset file not found: {testset_path}"
            }

        testset = self.load_testset(testset_path)
        print(f"Topology: {testset.get('topology', 'N/A')}")
        print(f"Requirement: {testset.get('requirement', 'N/A')}")
        print(f"Verification: {testset.get('verification', 'N/A')}")

        # Check if config directory exists
        config_dir = os.path.join(results_dir, f"{testset_id}_cisco")
        if not os.path.exists(config_dir):
            return {
                "testset_id": testset_id,
                "status": "error",
                "message": f"Config directory not found: {config_dir}",
                "config_type": config_type
            }

        # Determine which config directory to use
        temp_dir = None
        if use_fixed:
            fixed_config_dir = os.path.join(config_dir, "configs_fixed")
            if not os.path.exists(fixed_config_dir):
                return {
                    "testset_id": testset_id,
                    "status": "error",
                    "message": f"Fixed config directory not found: {fixed_config_dir}",
                    "config_type": config_type
                }
            # Create a temporary snapshot directory structure for Batfish
            import tempfile
            import shutil
            temp_dir = tempfile.mkdtemp()
            temp_configs_dir = os.path.join(temp_dir, "configs")
            os.makedirs(temp_configs_dir)

            # Copy fixed configs to temp directory
            for cfg_file in os.listdir(fixed_config_dir):
                if cfg_file.endswith('.cfg'):
                    shutil.copy2(
                        os.path.join(fixed_config_dir, cfg_file),
                        os.path.join(temp_configs_dir, cfg_file)
                    )
            snapshot_dir = temp_dir
        else:
            snapshot_dir = config_dir

        # Load snapshot
        network_name = f"cisco_testset_{testset_id}_{'fixed' if use_fixed else 'original'}"
        snapshot_name = "snapshot"

        print(f"\nLoading snapshot from: {snapshot_dir}")
        try:
            self.load_snapshot(snapshot_dir, network_name, snapshot_name)
            print("✓ Snapshot loaded successfully")
        except Exception as e:
            return {
                "testset_id": testset_id,
                "status": "error",
                "message": f"Failed to load snapshot: {str(e)}",
                "config_type": config_type
            }
        finally:
            # Clean up temporary directory if created
            if temp_dir is not None:
                import shutil
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass

        # Parse verification requirements or use structured tasks if present
        verification_text = testset.get('verification', '')
        if isinstance(testset.get("verification_tasks"), list):
            tasks = testset["verification_tasks"]
        else:
            tasks = self.parse_verification_requirements(verification_text)

        print(f"\nFound {len(tasks)} verification task(s)")

        # Execute verification tasks
        results = []
        all_passed = True

        for i, task in enumerate(tasks, 1):
            desc = task.get('description', f"Task type: {task.get('type', 'unknown')}")
            print(f"\n[{i}/{len(tasks)}] {desc}")

            success, message, debug_obj = None, None, {}
            try:
                res = None
                if task['type'] == 'bgp_session':
                    res = self.check_bgp_session_status()
                elif task['type'] == 'bgp_session_between':
                    res = self.check_bgp_session_between(task['a_node'], task['b_node'], task.get('expect', 'ESTABLISHED'))
                elif task['type'] == 'ospf_neighbor':
                    res = self.check_ospf_neighbors()
                elif task['type'] == 'ospf_neighbor_count':
                    res = self.check_ospf_neighbor_count(task['node'], int(task.get('expect', 0)))
                elif task['type'] == 'ospf_area_contains':
                    res = self.check_ospf_area_contains(task['area'], task['nodes'])
                elif task['type'] == 'ospf_nssa_present':
                    res = self.check_ospf_nssa_present(task['area'])
                elif task['type'] == 'ospf_abr_present':
                    res = self.check_ospf_abr_present(task['node'], task.get('areas', []))
                elif task['type'] == 'reachability':
                    res = self.check_reachability(task['src_node'], task['dst_ip'])
                elif task['type'] == 'route_exists':
                    net = task.get('network', task.get('prefix'))
                    if not net:
                        raise KeyError('network')
                    res = self.check_route_exists(task['node'], net)
                elif task['type'] == 'bgp_rib_contains':
                    res = self.check_bgp_rib_contains(task['node'], task['prefix'])
                elif task['type'] == 'bgp_advertised_contains':
                    res = self.check_bgp_advertised_contains(task['node'], task['prefix'])
                elif task['type'] == 'bgp_received_only':
                    res = self.check_bgp_received_only(task['node'], task.get('allowed_prefixes', []))
                elif task['type'] == 'no_static_route':
                    res = self.check_no_static_route(task['node'], task['prefix'])
                elif task['type'] == 'ospf_lsa_summary_present':
                    res = self.check_ospf_lsa_summary_present(task.get('from_area', '0'), task.get('to_area', '0'), task.get('node'))
                elif task['type'] == 'no_ospf_external_on_border':
                    res = self.check_no_ospf_external_on_border(task.get('area', '0'))
                else:
                    success, message = False, f"Unknown task type: {task['type']}"
                if res is not None:
                    if isinstance(res, tuple) and len(res) == 3:
                        success, message, debug_obj = res
                    elif isinstance(res, tuple) and len(res) == 2:
                        success, message = res
            except Exception as e:
                success, message = False, f"Task execution error: {e}"

            debug_path = ""
            if debug_obj:
                debug_path = self._dump_debug(debug_base, testset_id, debug_config_type, i, task['type'], debug_obj)

            status_icon = "✓" if success else "✗"
            print(f"  {status_icon} {message}")

            results.append({
                "task": task.get('description', f"Task type: {task.get('type','unknown')}"),
                "type": task['type'],
                "success": success,
                "message": message,
                "debug_path": debug_path
            })

            if not success:
                all_passed = False

        # Summary
        passed_count = sum(1 for r in results if r['success'])
        total_count = len(results)

        return {
            "testset_id": testset_id,
            "status": "passed" if all_passed else "failed",
            "passed": passed_count,
            "total": total_count,
            "tasks": results,
            "topology": testset.get('topology', ''),
            "requirement": testset.get('requirement', ''),
            "verification": testset.get('verification', ''),
            "config_type": config_type
        }

    def get_testsets_with_fixed_configs(self, results_dir: str) -> List[int]:
        """
        Find all testset IDs that have fixed configs.

        Args:
            results_dir: Directory containing generated configs

        Returns:
            List of testset IDs that have fixed/ subdirectories
        """
        testsets_with_fixed = []
        for testset_id in range(1, 11):
            fixed_config_dir = os.path.join(results_dir, f"{testset_id}_cisco", "configs_fixed")
            if os.path.exists(fixed_config_dir):
                testsets_with_fixed.append(testset_id)
        return testsets_with_fixed

    def verify_all_testsets(self, testset_dir: str, results_dir: str,
                           testset_ids: List[int] = None, verify_fixed: bool = False,
                           verify_both: bool = False) -> List[Dict]:
        """
        Verify all testsets or a subset.

        Args:
            testset_dir: Directory containing testset JSON files
            results_dir: Directory containing generated configs
            testset_ids: List of testset IDs to verify (default: 1-10)
            verify_fixed: If True, only verify fixed configs
            verify_both: If True, verify both original and fixed configs

        Returns:
            List of verification results for each testset
        """
        if testset_ids is None:
            testset_ids = list(range(1, 11))

        all_results = []

        for testset_id in testset_ids:
            if verify_both:
                # Verify original configs
                result = self.verify_testset(testset_id, testset_dir, results_dir, use_fixed=False)
                all_results.append(result)

                # Check if fixed configs exist, if so verify them
                fixed_config_dir = os.path.join(results_dir, f"{testset_id}_cisco", "configs_fixed")
                if os.path.exists(fixed_config_dir):
                    result_fixed = self.verify_testset(testset_id, testset_dir, results_dir, use_fixed=True)
                    all_results.append(result_fixed)
            else:
                # Verify only original or only fixed
                result = self.verify_testset(testset_id, testset_dir, results_dir, use_fixed=verify_fixed)
                all_results.append(result)

        return all_results

    def generate_report(self, results: List[Dict], output_path: str):
        """Generate a detailed verification report."""

        # Save JSON report
        json_path = output_path.replace('.txt', '.json') if output_path.endswith('.txt') else output_path + '.json'
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        # Generate text report
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 100 + "\n")
            f.write("CISCO CONFIGURATION VERIFICATION REPORT\n")
            f.write("=" * 100 + "\n\n")

            # Summary statistics
            total_testsets = len(results)
            passed_testsets = sum(1 for r in results if r.get('status') == 'passed')
            failed_testsets = total_testsets - passed_testsets

            f.write(f"Total Testsets: {total_testsets}\n")
            f.write(f"Passed: {passed_testsets}\n")
            f.write(f"Failed: {failed_testsets}\n")
            f.write(f"Success Rate: {passed_testsets/total_testsets*100:.1f}%\n")
            f.write("\n" + "=" * 100 + "\n\n")

            # Detailed results for each testset
            for result in results:
                testset_id = result['testset_id']
                status = result.get('status', 'unknown')
                config_type = result.get('config_type', 'Original')

                f.write(f"\nTestset {testset_id} ({config_type}): {status.upper()}\n")
                f.write("-" * 100 + "\n")

                if 'topology' in result:
                    f.write(f"Topology: {result['topology']}\n")
                if 'requirement' in result:
                    f.write(f"Requirement: {result['requirement']}\n")
                if 'verification' in result:
                    f.write(f"Verification: {result['verification']}\n")

                if status == 'error':
                    f.write(f"\nError: {result.get('message', 'Unknown error')}\n")
                else:
                    f.write(f"\nVerification Results: {result.get('passed', 0)}/{result.get('total', 0)} tasks passed\n")

                    if 'tasks' in result:
                        for task in result['tasks']:
                            status_icon = "✓" if task['success'] else "✗"
                            f.write(f"\n  {status_icon} {task['task']}\n")
                            f.write(f"    {task['message']}\n")

                f.write("\n")

            f.write("=" * 100 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 100 + "\n")

        print(f"\n✓ Report saved to: {output_path}")
        print(f"✓ JSON report saved to: {json_path}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify Cisco configurations against testset requirements"
    )
    parser.add_argument(
        "--testset-dir",
        default="testset_json_cisco",
        help="Directory containing testset JSON files (default: testset_json_cisco)"
    )
    parser.add_argument(
        "--results-dir",
        default="results_cisco",
        help="Directory containing generated configs (default: results_cisco)"
    )
    parser.add_argument(
        "--output",
        default="cisco_verify/verification_report.txt",
        help="Output report path (default: cisco_verify/verification_report.txt)"
    )
    parser.add_argument(
        "--testset-ids",
        type=int,
        nargs='+',
        help="Specific testset IDs to verify (default: all 1-10)"
    )
    parser.add_argument(
        "--batfish-host",
        default="192.168.31.170",
        help="Batfish server host (default: 192.168.31.170)"
    )
    parser.add_argument(
        "--batfish-port",
        type=int,
        default=9996,
        help="Batfish server port (default: 9996)"
    )
    parser.add_argument(
        "--verify-fixed",
        action="store_true",
        help="Verify only fixed configs (from configs_fixed/ directories)"
    )
    parser.add_argument(
        "--verify-both",
        action="store_true",
        help="Verify both original and fixed configs"
    )

    args = parser.parse_args()

    # Create output directory if needed
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Initialize verifier
    verifier = CiscoConfigVerifier(
        batfish_host=args.batfish_host,
        batfish_port=args.batfish_port
    )

    # Show testsets with fixed configs
    testsets_with_fixed = verifier.get_testsets_with_fixed_configs(args.results_dir)
    if testsets_with_fixed:
        print(f"\nTestsets with fixed configs: {testsets_with_fixed}")

    # Determine which mode we're running in
    if args.verify_both:
        print("\nMode: Verifying both original and fixed configs")
    elif args.verify_fixed:
        print("\nMode: Verifying only fixed configs")
        if not testsets_with_fixed:
            print("Warning: No fixed configs found!")
    else:
        print("\nMode: Verifying original configs")

    # Run verification
    results = verifier.verify_all_testsets(
        testset_dir=args.testset_dir,
        results_dir=args.results_dir,
        testset_ids=args.testset_ids,
        verify_fixed=args.verify_fixed,
        verify_both=args.verify_both
    )

    # Generate report
    verifier.generate_report(results, args.output)

    # Print summary
    print("\n" + "=" * 100)
    print("VERIFICATION SUMMARY")
    print("=" * 100)

    passed = sum(1 for r in results if r.get('status') == 'passed')
    failed = sum(1 for r in results if r.get('status') == 'failed')
    errors = sum(1 for r in results if r.get('status') == 'error')

    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Errors: {errors}")
    print(f"Total:  {len(results)}")
    print("=" * 100)


if __name__ == "__main__":
    main()