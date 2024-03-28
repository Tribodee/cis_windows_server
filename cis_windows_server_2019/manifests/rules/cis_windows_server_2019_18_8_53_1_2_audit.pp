class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_53_1_2_audit {
  exec {'cis_windows_server_2019_18_8_53_1_2_audit_ensure_enable_windows_ntp_server_is_set_to_disabled_ms_only':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpServer\Enabled')
  }
}
