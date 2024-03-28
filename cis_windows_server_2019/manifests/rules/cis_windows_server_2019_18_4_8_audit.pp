class cis_windows_server_2019::rules::cis_windows_server_2019_18_4_8_audit {
  exec {'cis_windows_server_2019_18_4_8_audit_ensure_mss_safedllsearchmode_enable_safe_dll_search_mode_recommended_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode')
  }
}
