class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_65_3_3_3_audit {
  exec {'cis_windows_server_2019_18_9_65_3_3_3_audit_ensure_do_not_allow_lpt_port_redirection_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableLPT', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableLPT')
  }
}
