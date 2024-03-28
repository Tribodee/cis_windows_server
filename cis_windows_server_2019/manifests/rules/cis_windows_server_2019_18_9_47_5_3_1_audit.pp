class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_47_5_3_1_audit {
  exec {'cis_windows_server_2019_18_9_47_5_3_1_audit_ensure_prevent_users_and_apps_from_accessing_dangerous_websites_is_set_to_enabled_block':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection')
  }
}
