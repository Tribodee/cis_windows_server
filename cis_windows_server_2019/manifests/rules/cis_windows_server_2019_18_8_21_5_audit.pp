class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_21_5_audit {
  exec {'cis_windows_server_2019_18_8_21_5_audit_ensure_turn_off_background_refresh_of_group_policy_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy')
  }
}
