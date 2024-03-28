class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_25_1_audit {
  exec {'cis_windows_server_2019_18_8_25_1_audit_ensure_support_device_authentication_using_certificate_is_set_to_enabled_automatic_devicepkinitbehavior':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior')
  }

  exec {'cis_windows_server_2019_18_8_25_1_audit_ensure_support_device_authentication_using_certificate_is_set_to_enabled_automatic_devicepkinitenabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled')
  }
}
