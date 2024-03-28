class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_10_audit {
  exec {'cis_windows_server_2019_2_2_10_audit_ensure_back_up_files_and_directories_is_set_to_administrators_backup_operators':
    unless  => cis_windows_server_2019::check_gpresult_users('BackupPrivilege','Administrators,Backup Operators'),
    command => cis_windows_server_2019::check_gpresult_value('BackupPrivilege'),
  }
}
