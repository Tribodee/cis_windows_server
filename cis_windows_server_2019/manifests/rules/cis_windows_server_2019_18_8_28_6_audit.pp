class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_28_6_audit {
  exec {'cis_windows_server_2019_18_8_28_6_audit_ensure_turn_off_picture_password_sign_in_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows\System\BlockDomainPicturePassword', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows\System\BlockDomainPicturePassword')
  }
}
