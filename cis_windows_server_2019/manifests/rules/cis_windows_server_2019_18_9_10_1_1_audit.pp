class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_10_1_1_audit {
  exec {'cis_windows_server_2019_18_9_10_1_1_audit_ensure_configure_enhanced_anti_spoofing_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing')
  }
}
