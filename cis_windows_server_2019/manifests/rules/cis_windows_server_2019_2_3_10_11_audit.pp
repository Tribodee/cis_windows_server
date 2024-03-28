class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_10_11_audit {
  exec {'cis_windows_server_2019_2_3_10_11_audit_ensure_network_access_restrict_clients_allowed_to_make_remote_calls_to_sam_is_set_to_administrators_remote_access_allow_ms_only':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM'),
  }
}
