class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_9_2_audit {
  exec {'cis_windows_server_2019_2_3_9_2_audit_ensure_microsoft_network_server_digitally_sign_communications_always_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'),
  }
}
