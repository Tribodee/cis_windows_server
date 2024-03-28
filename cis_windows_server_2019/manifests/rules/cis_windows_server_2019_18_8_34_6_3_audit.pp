class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_34_6_3_audit {
  exec {'cis_windows_server_2019_18_8_34_6_3_audit_ensure_require_a_password_when_a_computer_wakes_on_battery_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex')
  }
}
