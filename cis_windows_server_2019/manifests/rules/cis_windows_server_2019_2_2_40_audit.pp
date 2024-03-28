class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_40_audit {
  exec {'cis_windows_server_2019_2_2_40_audit_ensure_modify_firmware_environment_values_is_set_to_administrators':
    unless  => cis_windows_server_2019::check_gpresult_users('SystemEnvironmentPrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('SystemEnvironmentPrivilege'),
  }
}
