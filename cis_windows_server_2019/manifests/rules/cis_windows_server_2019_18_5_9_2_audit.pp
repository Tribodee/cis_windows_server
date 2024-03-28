class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_9_2_audit {
  exec {'cis_windows_server_2019_18_5_9_2_audit_ensure_turn_on_responder_rspndr_driver_is_set_to_enabled_allowrspndrondomain':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain')
  }

  exec {'cis_windows_server_2019_18_5_9_2_audit_ensure_turn_on_responder_rspndr_driver_is_set_to_enabled_allowrspndronpublicnet':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet')
  }

  exec {'cis_windows_server_2019_18_5_9_2_audit_ensure_turn_on_responder_rspndr_driver_is_set_to_enabled_enablerspndr':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableRspndr', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableRspndr')
  }

    exec {'cis_windows_server_2019_18_5_9_2_audit_ensure_turn_on_responder_rspndr_driver_is_set_to_enabled_prohibitrspndronprivatenet':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet')
  }
}
