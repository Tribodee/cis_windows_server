class cis_windows_server_2019::rules::cis_windows_server_2019_1_1_5_audit{
  exec {'cis_windows_server_2019_1_1_5_audit_ensure_password_must_meet_complexity_requirements_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult('PasswordComplexity','Enabled'),
    command => cis_windows_server_2019::check_gpresult_value('PasswordComplexity'),
  }
}
