class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_89_1_audit {
  exec {'cis_windows_server_2019_18_9_89_1_audit_ensure_allow_suggested_apps_in_windows_ink_workspace_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowSuggestedAppsInWindowsInkWorkspace')
  }
}
