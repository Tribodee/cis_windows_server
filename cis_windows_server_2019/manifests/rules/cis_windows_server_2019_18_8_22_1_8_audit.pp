class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_22_1_8_audit {
  exec {'cis_windows_server_2019_18_8_22_1_8_audit_ensure_turn_off_search_companion_content_file_updates_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\SearchCompanion\DisableContentFileUpdates', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\SearchCompanion\DisableContentFileUpdates')
  }
}
