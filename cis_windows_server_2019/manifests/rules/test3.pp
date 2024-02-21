#Testing modules gpresult
class cis_windows_server_2019::rules::test3 {
  $gpresult_raw = $facts['gpresult_facts']
  notify {"${gpresult_raw}":}
}

