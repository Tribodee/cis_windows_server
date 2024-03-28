class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_6_1_audit {
  exec {'cis_windows_server_2019_2_3_6_1_audit_ensure_domain_member_digitally_encrypt_or_sign_secure_channel_data_always_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal'),
  }
}
