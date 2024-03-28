class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_2_2_audit {
  exec {'cis_windows_server_2019_2_3_2_2_audit_ensure_audit_shut_down_system_immediately_if_unable_to_log_security_audits_is_set_to_disabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail'),
  }
}
