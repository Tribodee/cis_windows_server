class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_10_10_audit {
  exec {'cis_windows_server_2019_2_3_10_10_audit_ensure_network_access_restrict_anonymous_access_to_named_pipes_and_shares_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess'),
  }
}
