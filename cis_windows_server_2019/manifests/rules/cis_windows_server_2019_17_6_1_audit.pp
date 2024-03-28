class cis_windows_server_2019::rules::cis_windows_server_2019_17_6_1_audit {
  exec { 'cis_windows_server_2019_17_6_1_audit_ensure_audit_detailed_file_share_is_set_to_include_failure':
    unless  => cis_windows_server_2019::check_auditpol('Detailed File Share', 'Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Detailed File Share'),
  }
}
