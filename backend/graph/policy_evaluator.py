"""Deterministic IAM Policy Evaluation Engine for CloudGuardian 2.0.

Provides deterministic evaluation of AWS IAM policies, statement effects,
action and resource wildcards, trust relationships, and condition keys.
Classifies attack paths into Confirmed, Potential, or Theoretical based on
authorization semantics, explicit Deny precedence, and runtime context.
"""
from fnmatch import fnmatchcase
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from backend.graph.iam_graph import EdgeType, IAMCapabilityGraph
from backend.scenarios.models import PathClassification, StatementSpec

logger = logging.getLogger("cloudguardian.graph.evaluator")


class PolicyEvaluator:
    """Deterministic evaluator for IAM policy statements, conditions, and trust relationships."""

    @staticmethod
    def match_wildcard(pattern: str, target: str) -> bool:
        """Evaluate case-insensitive wildcard matching for IAM actions, resources, and ARNs.

        Supports standard AWS glob patterns: '*' (zero or more chars) and '?' (single char).
        """
        if not pattern or not target:
            return False
        if pattern == "*":
            return True
        return fnmatchcase(target.lower(), pattern.lower())

    @classmethod
    def matches_action(cls, pattern_or_list: Union[str, List[str]], target_action: str) -> bool:
        """Check if target action matches statement action specification."""
        if not target_action:
            return False
        patterns = [pattern_or_list] if isinstance(pattern_or_list, str) else list(pattern_or_list)
        return any(cls.match_wildcard(p, target_action) for p in patterns)

    @classmethod
    def matches_resource(cls, pattern_or_list: Union[str, List[str]], target_resource: str) -> bool:
        """Check if target resource matches statement resource specification."""
        if not target_resource:
            return False
        patterns = [pattern_or_list] if isinstance(pattern_or_list, str) else list(pattern_or_list)
        return any(cls.match_wildcard(p, target_resource) for p in patterns)

    @classmethod
    def evaluate_condition_operator(
        cls,
        operator: str,
        key: str,
        expected_val: Any,
        context: Dict[str, Any],
    ) -> bool:
        """Evaluate a single IAM condition operator against runtime context."""
        actual_val = context.get(key)
        # Normalize key lookups (e.g. "aws:MultiFactorAuthPresent" vs "mfa_present")
        if actual_val is None:
            norm_key = key.split("/")[-1].split(":")[-1].lower()
            key_aliases = {
                "multifactorauthpresent": "mfa_present",
                "sourceip": "source_ip",
                "principalarn": "caller_arn",
                "username": "caller_name",
            }
            alias = key_aliases.get(norm_key, norm_key)
            actual_val = context.get(alias)

        op_lower = operator.lower()

        # 1. Boolean conditions
        if op_lower in ("bool", "boolifexists"):
            if actual_val is None:
                return op_lower == "boolifexists"
            expected_bool = str(expected_val).strip().lower() in ("true", "1", "yes")
            actual_bool = bool(actual_val) if not isinstance(actual_val, str) else actual_val.lower() in ("true", "1", "yes")
            return expected_bool == actual_bool

        # 2. String conditions
        if "stringequals" in op_lower:
            if actual_val is None:
                return "ifexists" in op_lower
            expected_list = expected_val if isinstance(expected_val, list) else [expected_val]
            return str(actual_val) in [str(e) for e in expected_list]

        if "stringnotequals" in op_lower:
            if actual_val is None:
                return "ifexists" in op_lower
            expected_list = expected_val if isinstance(expected_val, list) else [expected_val]
            return str(actual_val) not in [str(e) for e in expected_list]

        if "stringlike" in op_lower:
            if actual_val is None:
                return "ifexists" in op_lower
            expected_list = expected_val if isinstance(expected_val, list) else [expected_val]
            return any(cls.match_wildcard(str(exp), str(actual_val)) for exp in expected_list)

        # 3. IP Address conditions
        if "ipaddress" in op_lower:
            if not actual_val:
                return "ifexists" in op_lower
            try:
                client_ip = ipaddress.ip_address(str(actual_val))
                cidrs = expected_val if isinstance(expected_val, list) else [expected_val]
                return any(client_ip in ipaddress.ip_network(str(c), strict=False) for c in cidrs)
            except Exception:
                return False

        # 4. Numeric conditions
        if "numeric" in op_lower:
            if actual_val is None:
                return "ifexists" in op_lower
            try:
                act_num = float(actual_val)
                exp_num = float(expected_val)
                if "equals" in op_lower:
                    return act_num == exp_num
                if "lessthan" in op_lower:
                    return act_num < exp_num
                if "greaterthan" in op_lower:
                    return act_num > exp_num
            except Exception:
                return False

        # Default fallback: equality check
        if actual_val is None:
            return False
        return str(actual_val) == str(expected_val)

    @classmethod
    def evaluate_conditions(cls, conditions: Dict[str, Any], context: Optional[Dict[str, Any]]) -> bool:
        """Evaluate a dictionary of IAM condition blocks.

        All operators and keys must evaluate to True for the condition block to succeed.
        """
        if not conditions:
            return True
        ctx = context or {}

        for op, key_dict in conditions.items():
            if not isinstance(key_dict, dict):
                continue
            for key, expected in key_dict.items():
                if not cls.evaluate_condition_operator(op, key, expected, ctx):
                    return False
        return True

    @classmethod
    def evaluate_statement(
        cls,
        statement: Union[StatementSpec, Dict[str, Any]],
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, bool]:
        """Evaluate a statement against an action, resource, and context.

        Returns:
            Tuple of (matches_allow: bool, matches_deny: bool)
        """
        if isinstance(statement, StatementSpec):
            effect = statement.effect
            actions = statement.actions
            resources = statement.resources
            conditions = statement.conditions
        elif isinstance(statement, dict):
            effect = statement.get("Effect", "Allow")
            raw_act = statement.get("Action", [])
            actions = [raw_act] if isinstance(raw_act, str) else list(raw_act)
            raw_res = statement.get("Resource", [])
            resources = [raw_res] if isinstance(raw_res, str) else list(raw_res)
            conditions = statement.get("Condition", {})
        else:
            return False, False

        # Check action match
        if not cls.matches_action(actions, action):
            return False, False

        # Check resource match
        if not cls.matches_resource(resources, resource):
            return False, False

        # Check conditions
        if not cls.evaluate_conditions(conditions, context):
            return False, False

        if effect == "Deny":
            return False, True
        return True, False

    @classmethod
    def evaluate_permissions(
        cls,
        statements: List[Union[StatementSpec, Dict[str, Any]]],
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Evaluate full authorization for action on resource across statements.

        Precedence rule:
        1. Explicit Deny overrides any Allow.
        2. Explicit Allow grants permission.
        3. Default Deny if no statement matches.

        Returns:
            "ALLOW", "DENY", or "DEFAULT_DENY"
        """
        has_allow = False
        for stmt in statements:
            matches_allow, matches_deny = cls.evaluate_statement(stmt, action, resource, context)
            if matches_deny:
                return "DENY"
            if matches_allow:
                has_allow = True

        return "ALLOW" if has_allow else "DEFAULT_DENY"

    @classmethod
    def evaluate_trust_policy(
        cls,
        trust_statements: List[Union[StatementSpec, Dict[str, Any]]],
        caller_arn: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Evaluate if role trust policy allows AssumeRole by caller principal.

        Returns True if trust policy has explicit Allow and no explicit Deny.
        """
        has_allow = False
        ctx = dict(context or {})
        ctx["caller_arn"] = caller_arn

        for stmt in trust_statements:
            if isinstance(stmt, StatementSpec):
                effect = stmt.effect
                actions = stmt.actions
                principals = stmt.principals
                conditions = stmt.conditions
            elif isinstance(stmt, dict):
                effect = stmt.get("Effect", "Allow")
                raw_act = stmt.get("Action", [])
                actions = [raw_act] if isinstance(raw_act, str) else list(raw_act)
                principals = stmt.get("Principal", {})
                conditions = stmt.get("Condition", {})
            else:
                continue

            # Must match sts:AssumeRole
            if not cls.matches_action(actions, "sts:AssumeRole"):
                continue

            # Check principal match
            matched_principal = False
            if principals == "*" or principals == {"AWS": "*"}:
                matched_principal = True
            elif isinstance(principals, dict):
                aws_princ = principals.get("AWS", [])
                aws_list = [aws_princ] if isinstance(aws_princ, str) else list(aws_princ)
                if any(cls.match_wildcard(p, caller_arn) for p in aws_list):
                    matched_principal = True
                # Service principal match (e.g. ec2.amazonaws.com)
                service_princ = principals.get("Service", [])
                service_list = [service_princ] if isinstance(service_princ, str) else list(service_princ)
                if any(cls.match_wildcard(p, caller_arn) for p in service_list):
                    matched_principal = True

            if not matched_principal:
                continue

            # Check condition
            if not cls.evaluate_conditions(conditions, ctx):
                continue

            if effect == "Deny":
                return False  # Explicit deny terminates
            if effect == "Allow":
                has_allow = True

        return has_allow

    @classmethod
    def classify_path(
        cls,
        graph_engine: IAMCapabilityGraph,
        path_nodes: List[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[PathClassification, str, List[Dict[str, Any]]]:
        """Classify a multi-hop attack path into Confirmed, Potential, or Theoretical.

        Evaluation rules:
        - Theoretical: Any hop is blocked by an explicit Deny, invalid trust policy,
          or unsatisfied condition (such as missing MFA).
        - Potential: Hop permissions permit action (e.g. PassRole), but require external
          service execution context (e.g. ec2:RunInstances or lambda:CreateFunction).
        - Confirmed: All hops have explicit Allow, no Deny, verified trust, and satisfied conditions.

        Returns:
            Tuple of (PathClassification, reasoning_summary, list_of_hop_evaluations)
        """
        if not path_nodes or len(path_nodes) < 2:
            return PathClassification.THEORETICAL, "Path must contain at least 2 nodes.", []

        ctx = context or {}
        g = graph_engine.graph
        hop_evaluations: List[Dict[str, Any]] = []
        is_potential = False

        for i in range(len(path_nodes) - 1):
            source_id = path_nodes[i]
            target_id = path_nodes[i + 1]

            if not g.has_edge(source_id, target_id):
                hop_evaluations.append({
                    "hop": i + 1,
                    "source": source_id,
                    "target": target_id,
                    "status": "MISSING_EDGE",
                    "reason": f"No direct transition edge exists between {source_id} and {target_id}.",
                })
                return PathClassification.UNVERIFIED, f"Hop {i+1} ({source_id} -> {target_id}) lacks a connecting capability edge.", hop_evaluations

            edge_data = dict(g[source_id][target_id])
            rel = edge_data.get("relationship", "")
            actions = edge_data.get("actions", [])
            evidence = edge_data.get("evidence", {})
            effect = edge_data.get("effect", "Allow")

            # Check for explicit Deny on edge
            if effect == "Deny":
                hop_evaluations.append({
                    "hop": i + 1,
                    "source": source_id,
                    "target": target_id,
                    "relationship": rel,
                    "status": "EXPLICIT_DENY",
                    "reason": f"Explicit Deny effect on capability edge {source_id} -> {target_id}.",
                })
                return PathClassification.BLOCKED, f"Hop {i+1} is blocked by an explicit Deny statement.", hop_evaluations

            # Evaluate AssumesRole trust policy
            if rel == EdgeType.ASSUMES_ROLE.value:
                target_node = g.nodes.get(target_id, {})
                trust_policy = target_node.get("evidence", {}).get("trust_policy") or target_node.get("trust_policy")
                source_arn = g.nodes.get(source_id, {}).get("arn", source_id)

                if trust_policy:
                    trust_stmts = trust_policy if isinstance(trust_policy, list) else [trust_policy]
                    trust_valid = cls.evaluate_trust_policy(trust_stmts, source_arn, ctx)
                    if not trust_valid:
                        hop_evaluations.append({
                            "hop": i + 1,
                            "source": source_id,
                            "target": target_id,
                            "relationship": rel,
                            "status": "TRUST_REJECTED",
                            "reason": f"Trust policy on {target_id} does not permit {source_arn} or condition failed.",
                        })
                        return PathClassification.BLOCKED, f"Hop {i+1} role trust relationship rejected for {source_arn}.", hop_evaluations

                # Check if MFA condition was required but missing
                if evidence.get("requires_mfa") and not ctx.get("mfa_present", False):
                    hop_evaluations.append({
                        "hop": i + 1,
                        "source": source_id,
                        "target": target_id,
                        "relationship": rel,
                        "status": "MFA_REQUIRED",
                        "reason": f"MFA token required by policy but not present in caller context.",
                    })
                    return PathClassification.BLOCKED, f"Hop {i+1} requires Multi-Factor Authentication.", hop_evaluations

            # Check PassRole external context requirement
            if rel == EdgeType.PASS_ROLE.value:
                is_potential = True
                hop_evaluations.append({
                    "hop": i + 1,
                    "source": source_id,
                    "target": target_id,
                    "relationship": rel,
                    "status": "REQUIRES_COMPUTE_TRIGGER",
                    "reason": f"PassRole capability requires compute context (EC2/Lambda) to execute.",
                })
                continue

            hop_evaluations.append({
                "hop": i + 1,
                "source": source_id,
                "target": target_id,
                "relationship": rel,
                "status": "PERMITTED",
                "actions": actions,
            })

        if is_potential:
            return PathClassification.POTENTIAL, "Path requires external compute trigger (e.g. ec2:RunInstances or lambda:CreateFunction) to exploit.", hop_evaluations

        return PathClassification.CONFIRMED, "All path transitions verified with explicit Allow, valid trust, and satisfied conditions.", hop_evaluations
