class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_22_1_5_audit {
  exec {'cis_windows_server_2019_18_8_22_1_5_audit_ensure_turn_off_internet_download_for_web_publishing_and_online_ordering_wizards_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices')
  }
}
