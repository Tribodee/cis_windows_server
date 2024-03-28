class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_89_2_audit {
  exec {'cis_windows_server_2019_18_9_89_2_audit_ensure_allow_windows_ink_workspace_is_set_to_enabled_on_but_disallow_access_above_lock_or_disabled_but_not_enabled_on':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace')
  }
}
