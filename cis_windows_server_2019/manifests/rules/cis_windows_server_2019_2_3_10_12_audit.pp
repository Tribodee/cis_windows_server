class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_10_12_audit {
  exec {'cis_windows_server_2019_2_3_10_12_audit_ensure_network_access_shares_that_can_be_accessed_anonymously_is_set_to_none':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares',''),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares'),
  }
}
