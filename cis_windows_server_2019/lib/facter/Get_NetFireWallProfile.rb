require 'facter'
require 'json'
Facter.add(:get_netfirewallprofile) do
    confine :kernel => 'windows'
    setcode do
        powershell_command = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command "Get-NetFireWallprofile -PolicyStore ActiveStore | Select-Object * -ExcludeProperty PS*, Cim*,Caption*,ElementName*,InstanceID*,Description*,DisabledInterfaceAliases*, __*"'
        result = Facter::Core::Execution.execute(powershell_command)
        begin
            profiles = result.split(/\n\n/).map do |profile|
                profile_hash = Hash[profile.scan(/(\S+)\s*:\s*([^\n]+)/).map { |k, v| [k.downcase, v] }]
                [profile_hash['profile'].downcase, profile_hash.map { |k, v| [k.downcase, v] }.to_h]
            end
            structured_fact = Hash[profiles]
            structured_fact.each do |profile, properties|
                properties.each do |property, value|
                    fact_name = "get_netfirewallprofile_#{profile}_#{property.downcase}"
                    Facter.add(fact_name) do
                        setcode { value }
                    end
                end
            end
        rescue JSON::ParserError => e
            result
        end
    end
end
