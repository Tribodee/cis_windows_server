class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_15_2_audit {
  exec {'cis_windows_server_2019_2_3_15_2_audit_ensure_system_objects_strengthen_default_permissions_of_internal_system_objects_e_g_symbolic_links_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode'),
  }
}
