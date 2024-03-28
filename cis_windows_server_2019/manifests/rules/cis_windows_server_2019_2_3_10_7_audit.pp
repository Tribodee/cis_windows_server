class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_10_7_audit {
  exec {'cis_windows_server_2019_2_3_10_7_audit_configure_network_access_named_pipes_that_can_be_accessed_anonymously_ms_only':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess'),
  }
}
