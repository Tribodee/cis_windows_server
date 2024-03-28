class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_22_1_3_audit {
  exec {'cis_windows_server_2019_18_8_22_1_3_audit_ensure_turn_off_handwriting_recognition_error_reporting_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports')
  }
}
