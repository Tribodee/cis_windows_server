class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_102_1_3_audit {
  exec {'cis_windows_server_2019_18_9_102_1_3_audit_ensure_disallow_digest_authentication_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest')
  }
}
