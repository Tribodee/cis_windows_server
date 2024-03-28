class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_28_7_audit {
  exec  {'cis_windows_server_2019_18_8_28_7_audit_ensure_turn_on_convenience_pin_sign_in_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows\System\AllowDomainPINLogon', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows\System\AllowDomainPINLogon')
  }
}
