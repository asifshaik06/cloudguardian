"""NetworkX IAM Capability Graph Engine for CloudGuardian 2.0.

Models IAM principals (users, roles, groups), IAM policies, and cloud resources
(S3 buckets, EC2 instances, KMS keys) as a directed capability graph.
Enables graph traversal, privilege escalation pathfinding, and attack blast-radius calculation.
"""
from enum import Enum
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import networkx as nx

logger = logging.getLogger("cloudguardian.graph.iam")


class NodeType(str, Enum):
    """Supported entity categories in the capability graph."""
    USER = "IAMUser"
    ROLE = "IAMRole"
    GROUP = "IAMGroup"
    POLICY = "IAMPolicy"
    S3 = "S3Bucket"
    EC2 = "EC2Instance"
    KMS = "KMSKey"


class EdgeType(str, Enum):
    """Supported relationship and capability edge types."""
    ASSUMES_ROLE = "AssumesRole"
    HAS_POLICY = "HasPolicy"
    CAN_ACCESS = "CanAccessResource"
    MEMBER_OF = "MemberOf"
    ATTACHED_TO = "AttachedTo"
    CAN_ESCALATE = "CanEscalateTo"
    PASS_ROLE = "PassRole"


# Default visual palette for ECharts rendering
CATEGORY_COLORS: Dict[NodeType, str] = {
    NodeType.USER: "#4dabf7",     # Soft blue
    NodeType.ROLE: "#ffa94d",     # Warm orange
    NodeType.GROUP: "#74c0fc",    # Sky blue
    NodeType.POLICY: "#ffd43b",   # Yellow
    NodeType.S3: "#69db7c",       # Mint green
    NodeType.EC2: "#da77f2",      # Lavender purple
    NodeType.KMS: "#20c997",      # Teal
}

CATEGORY_INDEX: Dict[NodeType, int] = {
    NodeType.USER: 0,
    NodeType.ROLE: 1,
    NodeType.GROUP: 2,
    NodeType.POLICY: 3,
    NodeType.S3: 4,
    NodeType.EC2: 5,
    NodeType.KMS: 6,
}

CRITICAL_ESCALATION_ACTIONS: Set[str] = {
    "iam:createaccesskey",
    "iam:createkey",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:attachgrouppolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:putgrouppolicy",
    "iam:updateassumerolepolicy",
    "iam:passrole",
    "sts:assumerole",
}


class IAMCapabilityGraph:
    """Directed graph representing AWS IAM access permissions, trust relationships, and resource access."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()

    def clear(self) -> None:
        """Clear all nodes and edges."""
        self.graph.clear()

    # ---- Node Operations ----

    def add_principal(
        self,
        node_id: str,
        name: str,
        principal_type: Union[NodeType, str] = NodeType.USER,
        is_admin: bool = False,
        policies: Optional[List[str]] = None,
        arn: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add an IAM User, Role, or Group node to the graph."""
        p_type = NodeType(principal_type) if isinstance(principal_type, str) else principal_type
        ev = evidence or {}
        self.graph.add_node(
            node_id,
            id=node_id,
            name=name,
            type=p_type.value,
            category=p_type,
            arn=arn or node_id,
            is_admin=is_admin,
            policies=policies or [],
            evidence=ev,
        )
        return node_id

    def add_policy(
        self,
        node_id: str,
        name: str,
        document: Optional[Dict[str, Any]] = None,
        statements: Optional[List[Dict[str, Any]]] = None,
        arn: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add an IAM Policy node."""
        ev = evidence or {}
        if document:
            ev["document"] = document
        self.graph.add_node(
            node_id,
            id=node_id,
            name=name,
            type=NodeType.POLICY.value,
            category=NodeType.POLICY,
            arn=arn or node_id,
            statements=statements or [],
            evidence=ev,
        )
        return node_id

    def add_resource(
        self,
        node_id: str,
        name: str,
        resource_type: Union[NodeType, str] = NodeType.S3,
        is_sensitive: bool = False,
        arn: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add a target AWS resource node (S3 bucket, EC2 instance, KMS key)."""
        r_type = NodeType(resource_type) if isinstance(resource_type, str) else resource_type
        ev = evidence or {}
        self.graph.add_node(
            node_id,
            id=node_id,
            name=name,
            type=r_type.value,
            category=r_type,
            arn=arn or node_id,
            is_sensitive=is_sensitive,
            evidence=ev,
        )
        return node_id

    # ---- Edge Operations ----

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship: Union[EdgeType, str],
        actions: Optional[List[str]] = None,
        effect: str = "Allow",
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a directed capability or trust relationship edge."""
        rel_str = relationship.value if isinstance(relationship, EdgeType) else str(relationship)
        act_list = actions or []
        ev = evidence or {}

        # If edge already exists, merge actions
        if self.graph.has_edge(source_id, target_id):
            existing = self.graph[source_id][target_id]
            merged_actions = list(set(existing.get("actions", []) + act_list))
            existing["actions"] = merged_actions
            if ev:
                existing_ev = existing.get("evidence", {})
                existing_ev.update(ev)
                existing["evidence"] = existing_ev
        else:
            self.graph.add_edge(
                source_id,
                target_id,
                relationship=rel_str,
                actions=act_list,
                effect=effect,
                evidence=ev,
            )

    # ---- Query Helpers ----

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve node attributes dictionary, or None if not found."""
        if self.graph.has_node(node_id):
            return dict(self.graph.nodes[node_id])
        return None

    def get_edge(self, source_id: str, target_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve edge attributes dictionary, or None if not found."""
        if self.graph.has_edge(source_id, target_id):
            return dict(self.graph[source_id][target_id])
        return None

    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    # ---- Policy Parsing ----

    @staticmethod
    def parse_policy_document(
        doc_or_json: Union[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Extract a normalized list of statement dictionaries from an IAM policy document."""
        if isinstance(doc_or_json, str):
            try:
                doc = json.loads(doc_or_json)
            except Exception:
                return []
        elif isinstance(doc_or_json, dict):
            doc = doc_or_json
        else:
            return []

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        elif not isinstance(statements, list):
            statements = []

        norm_statements: List[Dict[str, Any]] = []
        for s in statements:
            if not isinstance(s, dict):
                continue
            effect = s.get("Effect", "Allow")
            raw_act = s.get("Action", [])
            actions = [raw_act] if isinstance(raw_act, str) else list(raw_act)
            raw_res = s.get("Resource", [])
            resources = [raw_res] if isinstance(raw_res, str) else list(raw_res)

            norm_statements.append({
                "Sid": s.get("Sid", ""),
                "Effect": effect,
                "Action": actions,
                "Resource": resources,
                "Condition": s.get("Condition", {}),
                "Principal": s.get("Principal", {}),
            })
        return norm_statements

    @staticmethod
    def is_admin_statement(stmt: Dict[str, Any]) -> bool:
        """Check if statement allows unrestricted administrative actions."""
        if stmt.get("Effect") != "Allow":
            return False
        actions = [a.lower() for a in stmt.get("Action", [])]
        resources = stmt.get("Resource", [])
        has_wildcard_action = "*" in actions or "*:*" in actions
        has_wildcard_resource = "*" in resources or not resources
        return has_wildcard_action and has_wildcard_resource

    # ---- AWS & Moto Ingestion ----

    def build_from_aws_or_moto(
        self,
        iam_client: Any = None,
        s3_client: Any = None,
        ec2_client: Any = None,
        populate_defaults_if_empty: bool = True,
    ) -> None:
        """Ingest live or simulated AWS resources into the capability graph.

        Connects via boto3 clients to scan Users, Roles, Policies, S3 Buckets, and EC2 Instances.
        If no resources exist or connection fails, safely falls back to default topology.
        """
        self.clear()
        ingested_count = 0

        # 1. Ingest IAM Users
        if iam_client:
            try:
                users_resp = iam_client.list_users()
                for u in users_resp.get("Users", []):
                    uname = u["UserName"]
                    u_arn = u.get("Arn", f"arn:aws:iam:::user/{uname}")
                    u_id = f"user/{uname}"
                    self.add_principal(
                        u_id,
                        name=uname,
                        principal_type=NodeType.USER,
                        arn=u_arn,
                        evidence={"created": str(u.get("CreateDate")), "user_id": u.get("UserId")},
                    )
                    ingested_count += 1

                    # Attached policies
                    try:
                        att_resp = iam_client.list_attached_user_policies(UserName=uname)
                        for pol in att_resp.get("AttachedPolicies", []):
                            pol_name = pol["PolicyName"]
                            pol_arn = pol["PolicyArn"]
                            pol_id = f"policy/{pol_name}"
                            is_adm = "AdministratorAccess" in pol_name
                            self.add_policy(pol_id, pol_name, arn=pol_arn)
                            self.add_relationship(
                                u_id,
                                pol_id,
                                EdgeType.HAS_POLICY,
                                actions=["*"] if is_adm else [],
                                evidence={"policy_arn": pol_arn},
                            )
                            if is_adm:
                                self.graph.nodes[u_id]["is_admin"] = True
                    except Exception as err:
                        logger.debug("Failed listing attached policies for %s: %s", uname, err)

                    # Inline policies
                    try:
                        in_resp = iam_client.list_user_policies(UserName=uname)
                        for in_name in in_resp.get("PolicyNames", []):
                            pol_id = f"policy/inline-{uname}-{in_name}"
                            self.add_policy(pol_id, in_name)
                            self.add_relationship(u_id, pol_id, EdgeType.HAS_POLICY)
                    except Exception as err:
                        logger.debug("Failed listing inline policies for %s: %s", uname, err)

            except Exception as exc:
                logger.warning("Could not ingest IAM users: %s", exc)

            # 2. Ingest IAM Roles & Trust Relationships
            try:
                roles_resp = iam_client.list_roles()
                for r in roles_resp.get("Roles", []):
                    rname = r["RoleName"]
                    r_arn = r.get("Arn", f"arn:aws:iam:::role/{rname}")
                    r_id = f"role/{rname}"
                    is_admin_role = "Admin" in rname

                    self.add_principal(
                        r_id,
                        name=rname,
                        principal_type=NodeType.ROLE,
                        arn=r_arn,
                        is_admin=is_admin_role,
                        evidence={"trust_document": r.get("AssumeRolePolicyDocument")},
                    )
                    ingested_count += 1

                    # Parse Trust Policy (AssumeRolePolicyDocument)
                    trust_doc = r.get("AssumeRolePolicyDocument")
                    if trust_doc:
                        stmts = self.parse_policy_document(trust_doc)
                        for stmt in stmts:
                            if stmt.get("Effect") == "Allow":
                                princ = stmt.get("Principal", {})
                                # Trust principal can be AWS ARN, Service, or wildcard
                                aws_princ = princ.get("AWS", [])
                                if isinstance(aws_princ, str):
                                    aws_princ = [aws_princ]
                                for p_entry in aws_princ:
                                    src_id = p_entry
                                    if "/" in p_entry:
                                        parts = p_entry.split("/")
                                        src_id = f"{parts[-2]}/{parts[-1]}"
                                    elif ":" in p_entry:
                                        src_id = p_entry.split(":")[-1]

                                    if not self.graph.has_node(src_id):
                                        self.add_principal(src_id, src_id, NodeType.USER)
                                    self.add_relationship(
                                        src_id,
                                        r_id,
                                        EdgeType.ASSUMES_ROLE,
                                        actions=["sts:AssumeRole"],
                                        evidence={"trust_statement": stmt},
                                    )

                    # Ingest attached role policies
                    try:
                        att_roles = iam_client.list_attached_role_policies(RoleName=rname)
                        for pol in att_roles.get("AttachedPolicies", []):
                            pol_name = pol["PolicyName"]
                            pol_arn = pol["PolicyArn"]
                            pol_id = f"policy/{pol_name}"
                            is_adm = "AdministratorAccess" in pol_name
                            self.add_policy(pol_id, pol_name, arn=pol_arn)
                            self.add_relationship(
                                r_id,
                                pol_id,
                                EdgeType.HAS_POLICY,
                                actions=["*"] if is_adm else [],
                                evidence={"policy_arn": pol_arn},
                            )
                            if is_adm:
                                self.graph.nodes[r_id]["is_admin"] = True
                    except Exception as err:
                        logger.debug("Failed listing attached policies for role %s: %s", rname, err)

            except Exception as exc:
                logger.warning("Could not ingest IAM roles: %s", exc)

        # 3. Ingest S3 Buckets
        if s3_client:
            try:
                b_resp = s3_client.list_buckets()
                for b in b_resp.get("Buckets", []):
                    bname = b["Name"]
                    b_id = f"s3/{bname}"
                    is_sens = "student" in bname or "record" in bname or "trail" in bname
                    ev_s3: Dict[str, Any] = {"created": str(b.get("CreationDate"))}

                    # Check Public Access Block
                    try:
                        pab = s3_client.get_public_access_block(Bucket=bname)
                        ev_s3["pab"] = pab.get("PublicAccessBlockConfiguration", {})
                    except Exception:
                        ev_s3["pab"] = None

                    self.add_resource(
                        b_id,
                        name=bname,
                        resource_type=NodeType.S3,
                        is_sensitive=is_sens,
                        evidence=ev_s3,
                    )
                    ingested_count += 1
            except Exception as exc:
                logger.warning("Could not ingest S3 buckets: %s", exc)

        # 4. Ingest EC2 Instances
        if ec2_client:
            try:
                ec2_resp = ec2_client.describe_instances()
                for res in ec2_resp.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        iid = inst["InstanceId"]
                        node_id = f"ec2/{iid}"
                        profile = inst.get("IamInstanceProfile", {}).get("Arn")
                        self.add_resource(
                            node_id,
                            name=iid,
                            resource_type=NodeType.EC2,
                            evidence={
                                "instance_type": inst.get("InstanceType"),
                                "state": inst.get("State", {}).get("Name"),
                                "profile": profile,
                            },
                        )
                        ingested_count += 1
                        # If instance profile references a role, link EC2 -> Role
                        if profile:
                            prof_role = profile.split("/")[-1]
                            role_id = f"role/{prof_role}"
                            if self.graph.has_node(role_id):
                                self.add_relationship(
                                    node_id,
                                    role_id,
                                    EdgeType.ASSUMES_ROLE,
                                    actions=["sts:AssumeRole"],
                                    evidence={"instance_profile": profile},
                                )
            except Exception as exc:
                logger.warning("Could not ingest EC2 instances: %s", exc)

        # If empty or fewer than 3 nodes, seed default topology
        if populate_defaults_if_empty and ingested_count < 3:
            logger.info("Ingestion returned %d nodes; seeding realistic default topology.", ingested_count)
            self.seed_default_topology()

    def seed_default_topology(self) -> None:
        """Seed a realistic multi-tier AWS scenario.

        Models:
        - `intern-dev`: Low-privilege developer user.
        - `dev-role`: Development role with EC2 launch & limited S3 permissions.
        - `cicd-deployer`: Pipeline service role with iam:PassRole permission.
        - `admin-role`: High-privilege role with full AdministratorAccess.
        - `student-records-demo`: Sensitive S3 bucket holding student records.
        - `main-trail-bucket`: CloudTrail S3 bucket.
        - `bastion-ec2`: EC2 bastion instance.

        Attack paths modeled:
        1. intern-dev -> dev-role (AssumesRole)
        2. dev-role -> bastion-ec2 (PassRole / ec2:RunInstances)
        3. dev-role -> admin-role (Privilege escalation via PassRole + AssumeRole)
        4. admin-role -> student-records-demo (s3:GetObject, s3:DeleteBucketPublicAccessBlock)
        """
        # Nodes: Users & Roles
        self.add_principal(
            "user/intern-dev",
            name="intern-dev",
            principal_type=NodeType.USER,
            arn="arn:aws:iam::123456789012:user/intern-dev",
            evidence={"contractor": True, "department": "engineering", "mfa_enabled": False},
        )
        self.add_principal(
            "role/dev-role",
            name="dev-role",
            principal_type=NodeType.ROLE,
            arn="arn:aws:iam::123456789012:role/dev-role",
            evidence={"trusted_service": "ec2.amazonaws.com"},
        )
        self.add_principal(
            "role/cicd-deployer",
            name="cicd-deployer",
            principal_type=NodeType.ROLE,
            arn="arn:aws:iam::123456789012:role/cicd-deployer",
            evidence={"automated": True},
        )
        self.add_principal(
            "role/admin-role",
            name="admin-role",
            principal_type=NodeType.ROLE,
            is_admin=True,
            arn="arn:aws:iam::123456789012:role/admin-role",
            evidence={"managed_by": "secops", "has_admin_policy": True},
        )

        # Nodes: Resources
        self.add_resource(
            "s3/student-records-demo",
            name="student-records-demo",
            resource_type=NodeType.S3,
            is_sensitive=True,
            arn="arn:aws:s3:::student-records-demo",
            evidence={"data_classification": "confidential", "contains_pii": True},
        )
        self.add_resource(
            "s3/main-trail-bucket",
            name="main-trail-bucket",
            resource_type=NodeType.S3,
            is_sensitive=True,
            arn="arn:aws:s3:::main-trail-bucket",
            evidence={"audit_store": True},
        )
        self.add_resource(
            "ec2/bastion-ec2",
            name="bastion-ec2",
            resource_type=NodeType.EC2,
            is_sensitive=False,
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f",
            evidence={"public_ip": "54.210.12.44", "sg": "web-sg"},
        )

        # Policies
        self.add_policy(
            "policy/AdministratorAccess",
            name="AdministratorAccess",
            arn="arn:aws:iam::aws:policy/AdministratorAccess",
            evidence={"description": "Full AWS access policy"},
        )
        self.add_policy(
            "policy/DevLimitedPolicy",
            name="DevLimitedPolicy",
            arn="arn:aws:iam::123456789012:policy/DevLimitedPolicy",
            evidence={"description": "Read-only S3 and AssumeRole"},
        )

        # Relationships
        # intern-dev -> DevLimitedPolicy
        self.add_relationship(
            "user/intern-dev",
            "policy/DevLimitedPolicy",
            EdgeType.HAS_POLICY,
            actions=["sts:AssumeRole", "s3:ListBucket"],
        )

        # intern-dev can assume dev-role
        self.add_relationship(
            "user/intern-dev",
            "role/dev-role",
            EdgeType.ASSUMES_ROLE,
            actions=["sts:AssumeRole"],
            evidence={"trust_relationship": "sts:AssumeRole granted to intern-dev"},
        )

        # dev-role can PassRole to ec2/bastion-ec2
        self.add_relationship(
            "role/dev-role",
            "ec2/bastion-ec2",
            EdgeType.PASS_ROLE,
            actions=["iam:PassRole", "ec2:RunInstances"],
            evidence={"technique": "T1548.005", "privilege_escalation": True},
        )

        # dev-role has escalation path to cicd-deployer via PassRole
        self.add_relationship(
            "role/dev-role",
            "role/cicd-deployer",
            EdgeType.CAN_ESCALATE,
            actions=["iam:PassRole", "iam:AttachRolePolicy"],
            evidence={"vulnerability": "Permissive role passing without resource constraint"},
        )

        # cicd-deployer can assume admin-role
        self.add_relationship(
            "role/cicd-deployer",
            "role/admin-role",
            EdgeType.ASSUMES_ROLE,
            actions=["sts:AssumeRole"],
            evidence={"trust": "Cross-service assume role trust document"},
        )

        # admin-role has AdministratorAccess
        self.add_relationship(
            "role/admin-role",
            "policy/AdministratorAccess",
            EdgeType.HAS_POLICY,
            actions=["*"],
        )

        # admin-role has full access to student records and audit bucket
        self.add_relationship(
            "role/admin-role",
            "s3/student-records-demo",
            EdgeType.CAN_ACCESS,
            actions=["s3:*", "s3:GetObject", "s3:DeleteBucketPublicAccessBlock"],
            evidence={"impact": "Exfiltration and public exposure"},
        )
        self.add_relationship(
            "role/admin-role",
            "s3/main-trail-bucket",
            EdgeType.CAN_ACCESS,
            actions=["s3:*", "s3:DeleteBucket"],
            evidence={"impact": "Defense evasion and log tampering"},
        )

    # ---- ECharts Visualization Serialization ----

    def export_echarts(
        self,
        highlight_path: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Serialize graph to Apache ECharts force-directed graph schema.

        Args:
            highlight_path: Optional ordered list of node IDs indicating an active attack path.

        Returns:
            Dictionary matching ECharts `series[type=graph]` data format.
        """
        path_set = set(highlight_path) if highlight_path else set()
        path_edges: Set[Tuple[str, str]] = set()
        if highlight_path and len(highlight_path) > 1:
            for i in range(len(highlight_path) - 1):
                path_edges.add((highlight_path[i], highlight_path[i + 1]))

        categories = [
            {"name": "IAM User"},
            {"name": "IAM Role"},
            {"name": "IAM Group"},
            {"name": "IAM Policy"},
            {"name": "S3 Bucket"},
            {"name": "EC2 Instance"},
            {"name": "KMS Key"},
        ]

        nodes = []
        for n_id, data in self.graph.nodes(data=True):
            cat_enum = data.get("category", NodeType.USER)
            cat_idx = CATEGORY_INDEX.get(cat_enum, 0)
            is_adm = data.get("is_admin", False)
            is_sens = data.get("is_sensitive", False)
            in_path = n_id in path_set

            # Compute visual size
            size = 26
            if is_adm:
                size = 38
            elif is_sens:
                size = 32
            elif cat_enum == NodeType.USER:
                size = 30

            base_color = CATEGORY_COLORS.get(cat_enum, "#adb5bd")
            border_color = "#ff6b6b" if in_path else ("#ff8787" if is_adm else "#ced4da")
            border_width = 3 if in_path else (2 if is_adm else 1)

            node_obj = {
                "id": n_id,
                "name": data.get("name", n_id),
                "category": cat_idx,
                "symbolSize": size,
                "value": data.get("type", "Unknown"),
                "is_admin": is_adm,
                "is_sensitive": is_sens,
                "in_attack_path": in_path,
                "evidence": data.get("evidence", {}),
                "itemStyle": {
                    "color": "#ff4d4f" if (in_path and is_adm) else base_color,
                    "borderColor": border_color,
                    "borderWidth": border_width,
                },
                "tooltip": {
                    "formatter": f"<b>{data.get('name', n_id)}</b><br/>Type: {data.get('type')}<br/>Admin: {is_adm}<br/>Sensitive: {is_sens}"
                },
            }
            nodes.append(node_obj)

        links = []
        for u, v, data in self.graph.edges(data=True):
            rel = data.get("relationship", "RelatesTo")
            actions = data.get("actions", [])
            in_path = (u, v) in path_edges

            line_color = "#ff4d4f" if in_path else "#868e96"
            line_width = 3.5 if in_path else 1.5
            line_type = "solid" if in_path else ("dashed" if rel == EdgeType.CAN_ESCALATE.value else "solid")

            link_obj = {
                "source": u,
                "target": v,
                "relationship": rel,
                "actions": actions,
                "in_attack_path": in_path,
                "evidence": data.get("evidence", {}),
                "lineStyle": {
                    "color": line_color,
                    "width": line_width,
                    "type": line_type,
                    "curveness": 0.12,
                },
                "label": {
                    "show": in_path or len(actions) > 0,
                    "formatter": rel,
                    "fontSize": 10,
                },
            }
            links.append(link_obj)

        return {
            "categories": categories,
            "nodes": nodes,
            "links": links,
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(links),
                "users": sum(1 for n in nodes if n["category"] == 0),
                "roles": sum(1 for n in nodes if n["category"] == 1),
                "resources": sum(1 for n in nodes if n["category"] in (4, 5, 6)),
            },
        }
