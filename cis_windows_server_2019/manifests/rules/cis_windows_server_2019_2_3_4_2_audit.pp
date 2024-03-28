class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_4_2_audit {
  exec {'cis_windows_server_2019_2_3_4_2_audit_ensure_devices_prevent_users_from_installing_printer_drivers_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers'),
  }
}
