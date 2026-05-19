from __future__ import annotations

from collections import deque

from src.models import EffectiveAccess, Group, PrivilegePath, Role, User


def _role_permissions(role: Role) -> set[str]:
    permissions = set(role.permissions) | set(role.sensitive_actions)
    permissions -= set(role.deny_permissions)
    if role.permissions_boundary:
        permissions &= set(role.permissions_boundary)
    return permissions


def _walk_groups(user: User, groups_by_id: dict[str, Group]) -> list[tuple[str, list[str]]]:
    """Return group id plus path from user through nested groups."""
    found: list[tuple[str, list[str]]] = []
    queue = deque((group_id, [user.display_name, group_id]) for group_id in user.assigned_groups)
    seen_paths = set()
    while queue:
        group_id, path = queue.popleft()
        key = (group_id, tuple(path))
        if key in seen_paths or group_id not in groups_by_id:
            continue
        seen_paths.add(key)
        found.append((group_id, path))
        group = groups_by_id[group_id]
        for parent_id in group.nested_groups:
            queue.append((parent_id, path + [parent_id]))
    return found


def resolve_effective_access(
    user: User,
    groups_by_id: dict[str, Group],
    roles_by_id: dict[str, Role],
) -> EffectiveAccess:
    direct_roles = set(user.direct_roles)
    inherited_roles: set[str] = set()
    permissions: set[str] = set()
    denied_permissions: set[str] = set()
    boundary_limited_permissions: set[str] = set()
    sensitive_permissions: set[str] = set()
    paths: list[PrivilegePath] = []
    max_privilege_level = 0
    nested_group_depth = 0

    for role_id in direct_roles:
        role = roles_by_id.get(role_id)
        if not role:
            continue
        role_perms = _role_permissions(role)
        permissions |= role_perms
        denied_permissions |= set(role.deny_permissions)
        boundary_limited_permissions |= (set(role.permissions) | set(role.sensitive_actions)) - role_perms
        sensitive_permissions |= set(role.sensitive_actions) & role_perms
        max_privilege_level = max(max_privilege_level, role.privilege_level)
        for permission in sorted(role_perms):
            paths.append(PrivilegePath(user.user_id, role_id, permission, [user.display_name, role.name, permission], False, 0))

    for group_id, path in _walk_groups(user, groups_by_id):
        group = groups_by_id[group_id]
        depth = max(0, len(path) - 2)
        nested_group_depth = max(nested_group_depth, depth)
        for role_id in group.assigned_roles:
            role = roles_by_id.get(role_id)
            if not role:
                continue
            inherited_roles.add(role_id)
            role_perms = _role_permissions(role)
            permissions |= role_perms
            denied_permissions |= set(role.deny_permissions)
            boundary_limited_permissions |= (set(role.permissions) | set(role.sensitive_actions)) - role_perms
            sensitive_permissions |= set(role.sensitive_actions) & role_perms
            max_privilege_level = max(max_privilege_level, role.privilege_level)
            for permission in sorted(role_perms):
                paths.append(
                    PrivilegePath(
                        user.user_id,
                        role_id,
                        permission,
                        path + [role.name, permission],
                        True,
                        depth,
                    )
                )

    return EffectiveAccess(
        user_id=user.user_id,
        direct_roles=direct_roles,
        inherited_roles=inherited_roles,
        permissions=permissions,
        denied_permissions=denied_permissions,
        boundary_limited_permissions=boundary_limited_permissions,
        sensitive_permissions=sensitive_permissions,
        paths=paths,
        max_privilege_level=max_privilege_level,
        nested_group_depth=nested_group_depth,
    )


def resolve_all_access(users: list[User], groups: list[Group], roles: list[Role]) -> dict[str, EffectiveAccess]:
    groups_by_id = {group.group_id: group for group in groups}
    roles_by_id = {role.role_id: role for role in roles}
    return {user.user_id: resolve_effective_access(user, groups_by_id, roles_by_id) for user in users}


def explain_permission_path(access: EffectiveAccess, permission: str) -> list[str]:
    return [" -> ".join(path.path) for path in access.paths if path.permission == permission]

