class cis_windows_server_2019::rules::audit_ensure_network_access_allow_anonymous_sid_name_translation_is_set_to_disabled{
  exec {'cis_windows_server_2019_2_3_10_1_audit_ensure_network_access_allow_anonymous_sid_name_translation_is_set_to_disabled':
    unless   => cis_windows_server_2019::check_gpresult('LSAAnonymousNameLookup','Not Enabled'),
    command => cis_windows_server_2019::check_gpresult_value('LSAAnonymousNameLookup'),
    logoutput => true,
  }
}
