class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_9_1_audit {
  exec {'cis_windows_server_2019_18_5_9_1_audit_ensure_turn_on_mapper_i_o_lltdio_driver_is_set_to_disabled_allowlltdioondoamin':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain')
  }

    exec {'cis_windows_server_2019_18_5_9_1_audit_ensure_turn_on_mapper_i_o_lltdio_driver_is_set_to_disabled_allowlltdioonpublicnet':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet')
  }

    exec {'cis_windows_server_2019_18_5_9_1_audit_ensure_turn_on_mapper_i_o_lltdio_driver_is_set_to_disabled_enablelltdio':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableLLTDIO', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableLLTDIO')
  }

    exec {'cis_windows_server_2019_18_5_9_1_audit_ensure_turn_on_mapper_i_o_lltdio_driver_is_set_to_disabled_prohibitlltdioonprivatenet':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet')
  }
}
