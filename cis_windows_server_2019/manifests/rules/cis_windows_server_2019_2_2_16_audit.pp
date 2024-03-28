class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_16_audit {
  exec {'cis_windows_server_2019_2_2_16_audit_ensure_create_permanent_shared_objects_is_set_to_no_one':
    unless  => cis_windows_server_2019::check_gpresult_users('CreatePermanentPrivilege','N/A'),
    command => cis_windows_server_2019::check_gpresult_value('CreatePermanentPrivilege'),
  }
}
