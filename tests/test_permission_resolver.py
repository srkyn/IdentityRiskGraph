from src.ingest import load_all_data
from src.permission_resolver import resolve_all_access


def test_nested_group_resolution_explains_privilege_path():
    data = load_all_data()
    access = resolve_all_access(data["users"], data["groups"], data["roles"])["u017"]
    paths = [" -> ".join(path.path) for path in access.paths]
    assert "r_global_admin" in access.inherited_roles
    assert access.nested_group_depth >= 2
    assert any("David User -> g_helpdesk_nested -> g_helpdesk -> g_it_ops -> g_priv_admins -> Global Admin Role -> delete_user" in path for path in paths)


def test_direct_vs_inherited_roles_are_separated():
    data = load_all_data()
    access = resolve_all_access(data["users"], data["groups"], data["roles"])["u021"]
    assert "r_sysadmin" in access.direct_roles
    assert "r_global_admin" in access.inherited_roles


def test_permissions_boundary_limits_effective_access():
    data = load_all_data()
    access = resolve_all_access(data["users"], data["groups"], data["roles"])["u023"]
    assert "export_payroll" in access.boundary_limited_permissions
    assert "export_payroll" not in access.permissions
