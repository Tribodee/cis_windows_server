class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_8_3_audit {
  exec {'cis_windows_server_2019_2_3_8_3_audit_ensure_microsoft_network_client_send_unencrypted_password_to_third_party_smb_servers_is_set_to_disabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword'),
  }
}
