class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_9_audit {
  exec {'cis_windows_server_2019_2_2_9_audit_ensure_allow_log_on_through_remote_desktop_services_is_set_to_administrators_remote_desktop_users_ms_only':
    unless => cis_windows_server_2019::check_gpresult_users('RemoteInteractiveLogonRight','Administrators,Remote Desktop Users'),
    command => cis_windows_server_2019::check_gpresult_value('RemoteInteractiveLogonRight'),
  }
}
