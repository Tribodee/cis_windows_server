class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_27_1_audit {
  exec {'cis_windows_server_2019_18_8_27_1_audit_ensure_disallow_copying_of_user_input_methods_to_the_system_account_for_sign_in_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn')
  }
}
