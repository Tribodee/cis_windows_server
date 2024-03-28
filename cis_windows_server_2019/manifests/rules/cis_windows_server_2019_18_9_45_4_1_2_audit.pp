class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_45_4_1_2_audit {
  exec {'cis_windows_server_2019_18_9_45_4_1_2_audit_ensure_configure_attack_surface_reduction_rules_set_the_state_for_each_asr_rule_is_configured':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('', '', '',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('')
  }
}
