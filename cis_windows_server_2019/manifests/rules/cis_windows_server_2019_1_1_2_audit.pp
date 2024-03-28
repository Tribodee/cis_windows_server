class cis_windows_server_2019::rules::cis_windows_server_2019_1_1_2_audit{
  exec {'cis_windows_server_2019_1_1_2_audit_ensure_maximum_password_age_is_set_to_90_or_fewer_days_but_not_0':
    unless => cis_windows_server_2019::check_gpresult('MaximumPasswordAge','90'),
    command => cis_windows_server_2019::check_gpresult_value('MaximumPasswordAge'),
  }
}
