class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_102_2_4_audit {
  exec {'cis_windows_server_2019_18_9_102_2_4_audit_ensure_disallow_winrm_from_storing_runas_credentials_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs')
  }
}
