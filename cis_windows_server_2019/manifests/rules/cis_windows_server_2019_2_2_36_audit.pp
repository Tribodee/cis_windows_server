class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_36_audit {
  exec {'cis_windows_server_2019_2_2_36_audit_ensure_log_on_as_a_batch_job_is_set_to_administrators_and_another_service_accounts':
    unless  => cis_windows_server_2019::check_gpresult_users('BatchLogonRight','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('BatchLogonRight'),
  }
}
