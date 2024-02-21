#Testing modules get_netfirewall
class cis_windows_server_2019::rules::test1 {
  $get_netfirewallprofile_raw = $facts['get_netfirewallprofile']
  $selected_profile = 'domain'
  if $get_netfirewallprofile_raw[$selected_profile]['logmaxsizekilobytes'] != '4096' {
    $profile_data = $get_netfirewallprofile_raw[$selected_profile]['logmaxsizekilobytes']
    fail("test001 is ${profile_data} ")
  }else{
    exec { 'Else_condition1':
      command    => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo 'Im else'",
      logoutput  => true,
    }
  }
}
