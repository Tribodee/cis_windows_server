class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_11_1_audit {
  exec {'cis_windows_server_2019_2_3_11_1_audit_ensure_network_security_allow_local_system_to_use_computer_identity_for_ntlm_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId'),
  }
}
