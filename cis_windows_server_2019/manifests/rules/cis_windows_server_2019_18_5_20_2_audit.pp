class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_20_2_audit {
  exec {'cis_windows_server_2019_18_5_20_2_audit_ensure_prohibit_access_of_the_windows_connect_now_wizards_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WCN\UI\DisableWcnUi', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WCN\UI\DisableWcnUi')
  }
}
