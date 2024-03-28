class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_108_4_1_audit {
  exec {'cis_windows_server_2019_18_9_108_4_1_audit_ensure_manage_preview_builds_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuilds', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuilds')
  }
}
