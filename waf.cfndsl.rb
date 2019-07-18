CloudFormation do

  if defined? type and type.downcase == 'regional'
    type = 'WAFRegional'
  else
    type = 'WAF'
  end
  Condition("AssociateWithResource", FnNot(FnEquals(Ref('AssociatedResourceArn'), '')))
  
  Description "#{component_name} - #{component_version}"

  safe_stack_name = FnJoin('', FnSplit('-', Ref('AWS::StackName')))

  # SQL injection match conditions
  sql_injection_match_sets.each do |name, sets|
    tuple_list = []

    sets.each do |tuple|
      object = {}
      object[:FieldToMatch] = {}
      object[:FieldToMatch][:Type] = tuple["field_type"]
      object[:FieldToMatch][:Data] = tuple["field_data"] if tuple.has_key?("field_data")
      object[:TextTransformation] = tuple["text_transformation"]

      tuple_list << object
    end

    Resource("#{safe_name(name)}MatchSet") do
      Type("AWS::#{type}::SqlInjectionMatchSet")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("SqlInjectionMatchTuples", tuple_list)
    end

  end if defined? sql_injection_match_sets

  # Cross-site scripting match conditions
  xss_match_sets.each do |name, sets|
    tuple_list = []

    sets.each do |tuple|
      object = {}
      object[:FieldToMatch] = {}
      object[:FieldToMatch][:Type] = tuple["field_type"]
      object[:FieldToMatch][:Data] = tuple["field_data"] if tuple.has_key?("field_data")
      object[:TextTransformation] = tuple["text_transformation"]

      tuple_list << object
    end

    Resource("#{safe_name(name)}MatchSet") do
      Type("AWS::#{type}::XssMatchSet")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("XssMatchTuples", tuple_list)
    end

  end if defined? xss_match_sets

  # Size constraint conditions
  size_constraint_sets.each do |name, sets|
    tuple_list = []

    sets.each do |tuple|
      object = {}
      object[:FieldToMatch] = {}
      object[:FieldToMatch][:Type] = tuple["field_type"]
      object[:FieldToMatch][:Data] = tuple["field_data"] if tuple.has_key?("field_data")
      object[:TextTransformation] = tuple["text_transformation"]
      object[:ComparisonOperator] = tuple["comparison_operator"]
      object[:Size] = tuple['size']

      tuple_list << object
    end

    Resource("#{safe_name(name)}Set") do
      Type("AWS::#{type}::SizeConstraintSet")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("SizeConstraints", tuple_list)
    end

  end if defined? size_constraint_sets

  # Byte match sets
  byte_match_sets.each do |name, sets|
    tuple_list = []

    sets.each do |tuple|
      object = {}
      object[:FieldToMatch] = {}
      object[:FieldToMatch][:Type] = tuple["field_type"]
      object[:FieldToMatch][:Data] = tuple["field_data"] if tuple.has_key?("field_data")
      object[:TextTransformation] = tuple["text_transformation"]
      object[:PositionalConstraint] = tuple["positional_constraint"]
      object[:TargetString] = tuple["target_string"]

      tuple_list << object
    end

    Resource("#{safe_name(name)}MatchSet") do
      Type("AWS::#{type}::ByteMatchSet")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("ByteMatchTuples", tuple_list)
    end

  end if defined? byte_match_sets

  # IP descriptor sets
  ip_sets.each do |name, sets|
    descriptor_list = []

    sets.each do |set|
      descriptor_list << {
        Type: set["type"] || "IPV4",
        Value: set["value"]
      }
    end

    Resource("#{safe_name(name)}IPSet") do
      Type("AWS::#{type}::IPSet")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("IPSetDescriptors", descriptor_list)
    end

  end if defined? ip_sets

  ## Create the Rules
  rules.each do |name, config|
    predicates = []

    config["predicates"].each do |predicate|
      case predicate['type']
      when 'RegexMatch'
        data_id = FnGetAtt(safe_name(predicate["condition_name"]), 'MatchID')  # A custom resource

      when 'ByteMatch', 'SqlInjectionMatch', 'XssMatch'
        data_id = Ref(safe_name(predicate["condition_name"]) + 'MatchSet')

      when 'SizeConstraint'
        data_id = Ref(safe_name(predicate["condition_name"]) + 'Set')

      when 'IPMatch'
        data_id = Ref(safe_name(predicate["condition_name"]) + 'IPSet')
      end

      predicates << {
          DataId: data_id,
          Negated: predicate["negated"],
          Type: predicate["type"]
        }
    end

    Resource(safe_name(name)) do
      Type("AWS::#{type}::Rule")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("MetricName", FnJoin('', [safe_stack_name, safe_name(name)]))
      Property("Predicates",  predicates)
    end

  end if defined? rules

  if defined? web_acl
    rules = []

    web_acl['rules'].each do |name, config|
      rules << {
        Action: { Type: config["action"] },
        Priority: config["priority"],
        RuleId: Ref(safe_name(name))
      }
    end

    Resource("WebACL") do
      Type("AWS::#{type}::WebACL")
      Property("Name", FnSub("${EnvironmentName}-#{web_acl['name']}"))
      Property("MetricName", FnJoin('', [safe_stack_name, safe_name(web_acl['name'])]))
      Property("DefaultAction", { "Type" => web_acl['default_action'] })
      Property("Rules", rules)
    end

    Output('WebACL', Ref('WebACL'))

    if type == 'WAFRegional'
      Resource("WebACLAssociation") do
        Condition 'AssociateWithResource'
        Type "AWS::WAFRegional::WebACLAssociation"
        Property("ResourceArn", Ref("AssociatedResourceArn"))
        Property("WebACLId", Ref('WebACL'))
      end
    end
  end

  if defined? custom_resource_rules
    custom_resource_rules.each do |name, config|

      if config['type'] == 'RateBasedRule'
        Resource("#{safe_name(name)}RateBasedRule") {
          Type 'Custom::WAFRateLimit'
          Property('ServiceToken', FnGetAtt(config['function_name'], 'Arn'))
          Property('RuleName',  FnSub("${EnvironmentName}-#{name}"))
          Property('IpSetName', FnSub("${EnvironmentName}-#{name}-ip-set"))
          Property('Region',    Ref("AWS::Region"))
          Property('WebACLId',  Ref(config['web_acl_id']))
          Property('Rate',      config['rate'])
          Property('Negated',   config['negated'])
          Property('Action',    config['action'])
          Property('Priority',  config['priority'])
          Property('Regional',  config['regional'])
          Property('IPSet',     generate_waf_ip_set(cr_ip_sets, ['rate_limit']))
        }
      end
    end
  end

end
