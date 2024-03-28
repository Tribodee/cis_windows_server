class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_48_audit {
  exec {'cis_windows_server_2019_2_2_48_audit_ensure_take_ownership_of_files_or_other_objects_is_set_to_administrators':
    unless  => cis_windows_server_2019::check_gpresult_users('TakeOwnershipPrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('TakeOwnershipPrivilege'),
  }
}
