class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_22_1_11_audit {
  exec {'cis_windows_server_2019_18_8_22_1_11_audit_ensure_turn_off_the_windows_messenger_customer_experience_improvement_program_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Messenger\Client\CEIP', '2, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Messenger\Client\CEIP')
  }
}
