"""Unit tests for NetworkX IAM Capability Graph Engine."""
import pytest
from backend.graph.iam_graph import (
    IAMCapabilityGraph,
    NodeType,
    EdgeType,
)


@pytest.fixture
def graph() -> IAMCapabilityGraph:
    return IAMCapabilityGraph()


def test_add_nodes_and_relationships(graph: IAMCapabilityGraph):
    u_id = graph.add_principal("user/alice", "alice", NodeType.USER)
    r_id = graph.add_principal("role/admin", "admin", NodeType.ROLE, is_admin=True)
    s_id = graph.add_resource("s3/confidential-data", "confidential-data", NodeType.S3, is_sensitive=True)

    assert graph.node_count() == 3
    assert graph.edge_count() == 0

    graph.add_relationship(
        u_id,
        r_id,
        EdgeType.ASSUMES_ROLE,
        actions=["sts:AssumeRole"],
        evidence={"via": "trust_policy"},
    )
    graph.add_relationship(
        r_id,
        s_id,
        EdgeType.CAN_ACCESS,
        actions=["s3:GetObject", "s3:PutObject"],
    )

    assert graph.edge_count() == 2

    # Check node attributes
    u_node = graph.get_node(u_id)
    assert u_node is not None
    assert u_node["name"] == "alice"
    assert u_node["type"] == NodeType.USER.value
    assert not u_node["is_admin"]

    r_node = graph.get_node(r_id)
    assert r_node is not None
    assert r_node["is_admin"] is True

    s_node = graph.get_node(s_id)
    assert s_node is not None
    assert s_node["is_sensitive"] is True

    # Check edge attributes
    edge = graph.get_edge(u_id, r_id)
    assert edge is not None
    assert edge["relationship"] == EdgeType.ASSUMES_ROLE.value
    assert "sts:AssumeRole" in edge["actions"]
    assert edge["evidence"]["via"] == "trust_policy"


def test_merge_relationship_actions(graph: IAMCapabilityGraph):
    graph.add_principal("user/bob", "bob")
    graph.add_resource("s3/bucket-a", "bucket-a")

    graph.add_relationship("user/bob", "s3/bucket-a", EdgeType.CAN_ACCESS, actions=["s3:GetObject"])
    graph.add_relationship("user/bob", "s3/bucket-a", EdgeType.CAN_ACCESS, actions=["s3:PutObject"])

    edge = graph.get_edge("user/bob", "s3/bucket-a")
    assert edge is not None
    assert set(edge["actions"]) == {"s3:GetObject", "s3:PutObject"}


def test_parse_policy_document():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAll",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
            {
                "Sid": "ReadOnlyS3",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "arn:aws:s3:::demo-bucket/*",
            },
        ],
    }

    stmts = IAMCapabilityGraph.parse_policy_document(doc)
    assert len(stmts) == 2
    assert IAMCapabilityGraph.is_admin_statement(stmts[0]) is True
    assert IAMCapabilityGraph.is_admin_statement(stmts[1]) is False

    # String action and string resource handling
    single_stmt = {"Statement": {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}}
    stmts_single = IAMCapabilityGraph.parse_policy_document(single_stmt)
    assert len(stmts_single) == 1
    assert stmts_single[0]["Action"] == ["sts:AssumeRole"]


def test_seed_default_topology(graph: IAMCapabilityGraph):
    graph.seed_default_topology()

    assert graph.node_count() >= 7
    assert graph.edge_count() >= 6

    # Verify key nodes exist
    assert graph.get_node("user/intern-dev") is not None
    assert graph.get_node("role/dev-role") is not None
    assert graph.get_node("role/admin-role") is not None
    assert graph.get_node("s3/student-records-demo") is not None

    # Verify admin node has admin flag
    admin_node = graph.get_node("role/admin-role")
    assert admin_node["is_admin"] is True

    # Verify student-records is marked sensitive
    records_node = graph.get_node("s3/student-records-demo")
    assert records_node["is_sensitive"] is True


def test_export_echarts(graph: IAMCapabilityGraph):
    graph.seed_default_topology()
    echarts_data = graph.export_echarts(
        highlight_path=["user/intern-dev", "role/dev-role", "role/admin-role", "s3/student-records-demo"]
    )

    assert "nodes" in echarts_data
    assert "links" in echarts_data
    assert "categories" in echarts_data
    assert "stats" in echarts_data

    assert len(echarts_data["categories"]) == 7
    assert len(echarts_data["nodes"]) >= 7

    # Check highlighted attack path nodes and edges
    highlighted_nodes = [n for n in echarts_data["nodes"] if n["in_attack_path"]]
    assert len(highlighted_nodes) == 4

    highlighted_links = [l for l in echarts_data["links"] if l["in_attack_path"]]
    # intern-dev -> dev-role is in the graph
    assert any(l["source"] == "user/intern-dev" and l["target"] == "role/dev-role" for l in highlighted_links)


def test_build_from_aws_or_moto_fallback(graph: IAMCapabilityGraph):
    # When clients are None, should fall back to seeding default topology
    graph.build_from_aws_or_moto(iam_client=None, s3_client=None, ec2_client=None)
    assert graph.node_count() >= 7
