class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_16_2_audit {
  exec {'cis_windows_server_2019_18_9_16_2_audit_ensure_enumerate_administrator_accounts_on_elevation_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators')
  }
}
