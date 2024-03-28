class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_2_1_audit {
  exec {'cis_windows_server_2019_2_3_2_1_audit_ensure_audit_force_audit_policy_subcategory_settings_windows_vista_or_later_to_override_audit_policy_category_settings_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'),
  }
}
