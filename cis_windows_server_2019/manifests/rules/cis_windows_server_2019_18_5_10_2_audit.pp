class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_10_2_audit {
  exec {'cis_windows_server_2019_18_5_10_2_audit_ensure_turn_off_microsoft_peer_to_peer_networking_services_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Peernet\Disabled', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Peernet\Disabled')
  }
}
