class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_35_audit {
  exec {'cis_windows_server_2019_2_2_35_audit_ensure_lock_pages_in_memory_is_set_to_no_one':
    unless  => cis_windows_server_2019::check_gpresult_users('LockMemoryPrivilege','N/A'),
    command => cis_windows_server_2019::check_gpresult_value('LockMemoryPrivilege'),
  }
}
