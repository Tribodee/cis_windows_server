class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_10_5_audit {
  exec {'cis_windows_server_2019_2_3_10_5_audit_ensure_network_access_let_everyone_permissions_apply_to_anonymous_users_is_set_to_disabled': 
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous'),
  }
}
