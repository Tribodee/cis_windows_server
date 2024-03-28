class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_91_1_audit {
  exec {'cis_windows_server_2019_18_9_91_1_audit_ensure_sign_in_last_interactive_user_automatically_after_a_system_initiated_restart_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn')
  }
}
