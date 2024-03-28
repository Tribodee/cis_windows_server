class cis_windows_server_2019::rules::cis_windows_server_2019_18_4_12_audit {
  exec {'cis_windows_server_2019_18_4_12_audit_ensure_mss_warninglevel_percentage_threshold_for_the_security_event_log_at_which_the_system_will_generate_a_warning_is_set_to_enabled_90_or_less':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('System\CurrentControlSet\Services\Eventlog\Security\WarningLevel', '90, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('System\CurrentControlSet\Services\Eventlog\Security\WarningLevel')
  }
}
