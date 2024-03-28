class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_11_6_audit {
  exec {'cis_windows_server_2019_2_3_11_6_audit_ensure_network_security_force_logoff_when_logon_hours_expire_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('ForceLogoffWhenHourExpire','Enabled'),
    command  => cis_windows_server_2019::check_gpresult_value('ForceLogoffWhenHourExpire'),
  }
}
