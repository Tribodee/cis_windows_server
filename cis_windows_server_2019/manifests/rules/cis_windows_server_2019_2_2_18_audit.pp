class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_18_audit {
  exec {'cis_windows_server_2019_2_2_18_audit_ensure_create_symbolic_links_is_set_to_administrators_nt_virtual_machine_virtual_machines_ms_only':
    unless  => cis_windows_server_2019::check_gpresult_users('CreateSymbolicLinkPrivilege','Administrators\Virtual Machines'),
    command => cis_windows_server_2019::check_gpresult_value('CreateSymbolicLinkPrivilege'),
  }
}
