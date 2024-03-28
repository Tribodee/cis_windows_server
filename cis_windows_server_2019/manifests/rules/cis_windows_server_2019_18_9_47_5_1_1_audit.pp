class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_47_5_1_1_audit {
  exec {'cis_windows_server_2019_18_9_47_5_1_1_audit_ensure_configure_attack_surface_reduction_rules_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('', '', '',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('')
  }
}
