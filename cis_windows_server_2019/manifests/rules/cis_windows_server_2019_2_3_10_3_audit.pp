class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_10_3_audit {
  exec {'cis_windows_server_2019_2_3_10_3_audit_ensure_network_access_do_not_allow_anonymous_enumeration_of_sam_accounts_and_shares_is_set_to_enabled_ms_only':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous'),
  }
}
