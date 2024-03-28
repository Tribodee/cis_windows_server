class cis_windows_server_2019::rules::cis_windows_server_2019_18_1_2_2_audit {
  exec {'cis_windows_server_2019_18_1_2_2_audit_ensure_allow_users_to_enable_online_speech_recognition_services_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization')
  }
}
