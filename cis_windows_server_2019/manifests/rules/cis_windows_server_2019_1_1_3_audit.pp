class cis_windows_server_2019::rules::cis_windows_server_2019_1_1_3_audit{
  exec {'cis_windows_server_2019_1_1_3_audit_ensure_minimum_password_age_is_set_to_1_or_more_day':
    unless => cis_windows_server_2019::check_gpresult('MinimumPasswordAge','1'),
    command => cis_windows_server_2019::check_gpresult_value('MinimumPasswordAge'),
  }
}
