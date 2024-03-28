class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_4_audit {
  exec {'cis_windows_server_2019_2_2_4_audit_ensure_act_as_part_of_the_operating_system_is_set_to_no_one':
    unless  => cis_windows_server_2019::check_gpresult_users("TcbPrivilege","N/A"),
    command => cis_windows_server_2019::check_gpresult_value("TcbPrivilege"),
  }
}
