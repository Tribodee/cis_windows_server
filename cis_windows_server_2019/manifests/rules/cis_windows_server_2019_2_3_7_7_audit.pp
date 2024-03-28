class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_7_7_audit {
  exec {'cis_windows_server_2019_2_3_7_7_audit_ensure_interactive_logon_prompt_user_to_change_password_before_expiration_is_set_to_between_5_and_14_days':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning','14'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning'),
  }
}
