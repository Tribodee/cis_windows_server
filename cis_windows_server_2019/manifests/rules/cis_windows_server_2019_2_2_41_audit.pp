class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_41_audit {
  exec {'cis_windows_server_2019_2_2_41_audit_ensure_perform_volume_maintenance_tasks_is_set_to_administrators':
    unless  => cis_windows_server_2019::check_gpresult_users('ManageVolumePrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('ManageVolumePrivilege'),
  }
}
