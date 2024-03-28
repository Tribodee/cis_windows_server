require 'facter'
Facter.add(:gpresult_facts) do
  confine :kernel => 'windows'
  setcode do
    gpresult_output = Facter::Core::Execution.execute('gpresult /r /scope:computer /v')
    resultant_sets = []
    current_set = {}
    parsing_resultant_set = false
    gpresult_output.each_line do |line|
      line_strip = line.strip
      parsing_resultant_set = true if line_strip =~ /^Resultant Set Of Policies for Computer/
      if parsing_resultant_set
        if line_strip.empty? || line_strip =~ /^-+$/  # Skip lines with empty or '-' lines
          computer_setting_keys = current_set.select { |_, v| v.nil? }.keys
          computer_setting_value = computer_setting_keys.join(',')
          # current_set["Computer Setting"] = computer_setting_value unless computer_setting_value.empty?
          current_set["Computer Setting"] ||= ""
          current_set["Value"] ||= ""
          current_set["Computer Setting"] += ", #{computer_setting_value}" unless computer_setting_value.empty?
          current_set.delete_if { |_, v| v.nil? }
          resultant_sets << current_set unless current_set.empty?
          current_set = {}
        else
          key, value = line_strip.split(':', 2).map(&:strip)
          current_set[key] = value.nil? ? nil : value.chomp
        end
      end
    end
    resultant_sets << current_set unless current_set.empty?
    # Transform to have only the value at the head
    transformed_sets = resultant_sets.map do |set|
      if set.key?('Folder Id')
        actual_value = set['Folder Id']
        set.delete('Folder Id')
        set.delete('Computer Setting')
        { actual_value.to_s => set }
      else
        actual_value = set['ValueName'] || set['Policy']
        set.delete('ValueName')
        set.delete('Policy')
        set.delete('Value')
        { actual_value.to_s => set }
      end
    end
    # Combine all transformed
    combined_hash = transformed_sets.reduce({}, :merge)
    combined_hash
  end
end
