class cis_windows_server_2019::rules::cis_windows_server_2019_1_1_4_audit{
  exec {'cis_windows_server_2019_1_1_4_audit_ensure_minimum_password_length_is_set_to_8_or_more_character':
    unless => cis_windows_server_2019::check_gpresult('MinimumPasswordLength','8'),
    command => cis_windows_server_2019::check_gpresult_value('MinimumPasswordLength'),
  }
}
