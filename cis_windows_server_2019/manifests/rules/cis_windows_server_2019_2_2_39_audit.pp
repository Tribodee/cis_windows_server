class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_39_audit {
  exec {'cis_windows_server_2019_2_2_39_audit_ensure_modify_an_object_label_is_set_to_no_one':
    unless  => cis_windows_server_2019::check_gpresult_users('RelabelPrivilege','N/A'),
    command => cis_windows_server_2019::check_gpresult_value('RelabelPrivilege'),
  }
}
