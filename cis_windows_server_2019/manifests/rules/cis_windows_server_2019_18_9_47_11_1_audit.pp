class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_47_11_1_audit {
  exec {'cis_windows_server_2019_18_9_47_11_1_audit_ensure_configure_watson_events_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts')
  }
}
