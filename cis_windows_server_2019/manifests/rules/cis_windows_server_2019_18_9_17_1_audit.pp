class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_17_1_audit {
  exec {'cis_windows_server_2019_18_9_17_1_audit_ensure_allow_diagnostic_data_is_set_to_enabled_diagnostic_data_off_not_recommended_or_enabled_send_required_diagnostic_data_automated':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry')
  }
}
