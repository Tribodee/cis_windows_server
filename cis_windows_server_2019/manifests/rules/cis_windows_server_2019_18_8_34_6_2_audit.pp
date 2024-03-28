class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_34_6_2_audit {
  exec {'cis_windows_server_2019_18_8_34_6_2_audit_ensure_allow_network_connectivity_during_connected_standby_plugged_in_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex')
  }
}
