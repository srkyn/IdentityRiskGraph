from __future__ import annotations

import tempfile
from pathlib import Path

import networkx as nx
from pyvis.network import Network

from src.models import EffectiveAccess, Group, Permission, Resource, Role, User


def build_identity_graph(
    users: list[User],
    groups: list[Group],
    roles: list[Role],
    permissions: list[Permission],
    resources: list[Resource],
    access_by_user: dict[str, EffectiveAccess],
    user_filter: str | None = None,
    critical_only: bool = False,
) -> nx.DiGraph:
    graph = nx.DiGraph()
    users_to_show = [user for user in users if not user_filter or user.user_id == user_filter]
    role_ids = {role.role_id for role in roles}
    permission_ids = {permission.permission_id for permission in permissions}

    for user in users_to_show:
        graph.add_node(user.user_id, label=user.display_name, type="user", title=user.email)
        for group_id in user.assigned_groups:
            graph.add_edge(user.user_id, group_id, label="member")

    for group in groups:
        graph.add_node(group.group_id, label=group.name, type="group", title=group.description)
        for parent in group.nested_groups:
            graph.add_edge(group.group_id, parent, label="nested")
        for role_id in group.assigned_roles:
            graph.add_edge(group.group_id, role_id, label="assigns")

    for role in roles:
        graph.add_node(role.role_id, label=role.name, type="role", title=role.description)
        for permission in role.permissions + role.sensitive_actions:
            if permission in permission_ids:
                graph.add_edge(role.role_id, permission, label="allows")

    for permission in permissions:
        graph.add_node(permission.permission_id, label=permission.name, type="permission", title=permission.description)

    for resource in resources:
        graph.add_node(resource.resource_id, label=resource.name, type="resource", title=f"{resource.cloud} {resource.sensitivity}")
        for permission in permission_ids:
            if resource.type.lower() in permission or resource.owner_department.lower() in permission:
                graph.add_edge(permission, resource.resource_id, label="touches")

    if critical_only:
        keep = set()
        for user in users_to_show:
            access = access_by_user[user.user_id]
            for path in access.paths:
                if path.nested_depth >= 2 or path.permission in access.sensitive_permissions:
                    keep.update(_resolve_path_ids(path.path, users, groups, roles))
                    keep.add(path.permission)
        keep |= {node for node, degree in graph.degree if degree > 0 and node in keep}
        graph = graph.subgraph(keep).copy()
    return graph


def _resolve_path_ids(path_labels: list[str], users: list[User], groups: list[Group], roles: list[Role]) -> set[str]:
    lookup = {user.display_name: user.user_id for user in users}
    lookup.update({group.group_id: group.group_id for group in groups})
    lookup.update({role.name: role.role_id for role in roles})
    return {lookup.get(label, label) for label in path_labels}


def render_pyvis(graph: nx.DiGraph) -> Path:
    colors = {
        "user": "#5eead4",
        "group": "#60a5fa",
        "role": "#f59e0b",
        "permission": "#fb7185",
        "resource": "#a78bfa",
    }
    net = Network(height="720px", width="100%", directed=True, bgcolor="#07111f", font_color="#e5eefb")
    net.toggle_physics(True)
    for node, data in graph.nodes(data=True):
        node_type = data.get("type", "other")
        net.add_node(
            node,
            label=data.get("label", node),
            title=data.get("title", node),
            color=colors.get(node_type, "#94a3b8"),
            shape="dot" if node_type != "resource" else "database",
            size=22 if node_type in {"user", "role"} else 16,
        )
    for source, target, data in graph.edges(data=True):
        net.add_edge(source, target, label=data.get("label", ""), color="#314158")
    path = Path(tempfile.gettempdir()) / "identityriskgraph.html"
    net.write_html(str(path), notebook=False)
    return path

