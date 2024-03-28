class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_20_1_audit {
  exec {'cis_windows_server_2019_18_5_20_1_audit_ensure_configuration_of_wireless_settings_using_windows_connect_now_is_set_to_disabled_enableregistrars':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars')
  }

  exec {'cis_windows_server_2019_18_5_20_1_audit_ensure_configuration_of_wireless_settings_using_windows_connect_now_is_set_to_disabled_disableupnpregistrar':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar')
  }

  exec {'cis_windows_server_2019_18_5_20_1_audit_ensure_configuration_of_wireless_settings_using_windows_connect_now_is_set_to_disabled_disableinband802dot11registrar':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar')
  }

  exec {'cis_windows_server_2019_18_5_20_1_audit_ensure_configuration_of_wireless_settings_using_windows_connect_now_is_set_to_disabled_disableflashconfigregistrar':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar')
  }

  exec {'cis_windows_server_2019_18_5_20_1_audit_ensure_configuration_of_wireless_settings_using_windows_connect_now_is_set_to_disabled_disablewpdregistrar':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar')
  }
}
