class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_53_1_1_audit {
  exec {'cis_windows_server_2019_18_8_53_1_1_audit_ensure_enable_windows_ntp_client_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient\Enabled')
  }
}
