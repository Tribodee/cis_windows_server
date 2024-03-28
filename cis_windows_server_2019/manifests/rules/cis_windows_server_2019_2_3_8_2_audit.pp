class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_8_2_audit {
  exec {'cis_windows_server_2019_2_3_8_2_audit_ensure_microsoft_network_client_digitally_sign_communications_if_server_agrees_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature'),
  }
}
