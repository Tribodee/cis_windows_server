#Testing modules gpresult
# class cis_windows_server_2019::rules::test3 {
#   $gpresult_raw = $facts['gpresult_facts']
#   notify {"${gpresult_raw}":}
# }

class cis_windows_server_2019::rules::test3{
  exec {'test':
    unless   => cis_windows_server_2019::check_gpresult_folder_id_value_greater('SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize','0, 16, 0, 0','Enabled'),
    command  => cis_windows_server_2019::check_gpresult_folder_id_value('SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'),
  }
}

