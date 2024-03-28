class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_9_5_audit {
  exec {'cis_windows_server_2019_2_3_9_5_audit_ensure_microsoft_network_server_server_spn_target_name_validation_level_is_set_to_accept_if_provided_by_client_or_higher_ms_only':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel'),
  }
}
