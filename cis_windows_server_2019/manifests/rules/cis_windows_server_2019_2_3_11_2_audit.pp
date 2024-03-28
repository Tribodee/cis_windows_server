class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_11_2_audit {
  exec {'cis_windows_server_2019_2_3_11_2_audit_ensure_network_security_allow_localsystem_null_session_fallback_is_set_to_disabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback'),
  }
}
