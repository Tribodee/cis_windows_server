class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_22_1_13_audit {
  exec {'cis_windows_server_2019_18_8_22_1_13_audit_ensure_turn_off_windows_error_reporting_is_set_to_enabled_doreport':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DoReport', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DoReport')
  }

    exec {'cis_windows_server_2019_18_8_22_1_13_audit_ensure_turn_off_windows_error_reporting_is_set_to_enabled_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled')
  }
}
