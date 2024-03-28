class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_22_1_4_audit {
  exec {'cis_windows_server_2019_18_8_22_1_4_audit_ensure_turn_off_internet_connection_wizard_if_url_connection_is_referring_to_microsoft_com_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard\ExitOnMSICW')
  }
}
