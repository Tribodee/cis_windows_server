class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_28_1_audit {
  exec {'cis_windows_server_2019_18_8_28_1_audit_ensure_block_user_from_showing_account_details_on_sign_in_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin')
  }
}
