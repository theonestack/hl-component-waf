def safe_name(str)
  # Convert a string to PascalCase
  strs = str.split(/[-,_]/)
  return strs.map { |s| s.capitalize }.join()
end


def generate_waf_ip_set(ip_set, ip_block_names)
  ip_set_desc = []

  ip_block_names.each do |block|
    if ip_set.key? block
      ip_set[block].each do |ip|
        ip_set_desc << { Type: 'IPV4', Value: ip['value'] }
      end
    else
      raise "IP block #{block} not found in provide ips"
    end
  end

  return ip_set_desc
end
