class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_15_1_audit {
  exec {'cis_windows_server_2019_2_3_15_1_audit_ensure_system_objects_require_case_insensitivity_for_non_windows_subsystems_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive'),
  }
}
