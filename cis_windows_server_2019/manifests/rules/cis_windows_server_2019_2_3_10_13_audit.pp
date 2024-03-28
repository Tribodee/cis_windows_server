class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_10_13_audit {
  exec {'cis_windows_server_2019_2_3_10_13_audit_Ensure_Network_access_Sharing_and_security_model_for_local_accounts_is_set_to_Classic_local_users_authenticate_as_themselves':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest'),
  }
}
