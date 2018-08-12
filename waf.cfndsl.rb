CloudFormation do

  Description "#{component_name} - #{component_version}"

  # SQL injection match conditions
  control_sqlinjectionmatchset.each do |sqlinjectionmatchset|
      sqlinjectionmatchtuple_list = []
      sqlinjectionmatchset["sqlinjectionmatchtuples"].each do |sqlinjectionmatchtuple|

          object = {}
          object[:FieldToMatch] = {}
          object[:FieldToMatch][:Type] = sqlinjectionmatchtuple["field_type"]
          object[:TextTransformation] = sqlinjectionmatchtuple["texttransformation"]
          object[:FieldToMatch][:Data] = sqlinjectionmatchtuple["field_data"] if sqlinjectionmatchtuple.has_key?("field_data")
          sqlinjectionmatchtuple_list << object

      end

      Resource("#{sqlinjectionmatchset["name"]}") do
        Type("AWS::WAF::SqlInjectionMatchSet")
        Property("Name", FnJoin("-", [ Ref('EnvironmentName'), sqlinjectionmatchset["name"]]))
        Property("SqlInjectionMatchTuples", sqlinjectionmatchtuple_list )
      end

  end if defined? control_sqlinjectionmatchset

  # Cross-site scripting match conditions
  control_wafrxssset.each do |wafrxssset|

      xssmatchtuple_list = []
      wafrxssset["xssmatchtuples"].each do |xssmatchtuple|

        object = {}
        object[:FieldToMatch] = {}
        object[:FieldToMatch][:Type] = xssmatchtuple["field_type"]
        object[:TextTransformation] = xssmatchtuple["texttransformation"]
        object[:FieldToMatch][:Data] = xssmatchtuple["field_data"] if xssmatchtuple.has_key?("field_data")
        xssmatchtuple_list << object

      end

      Resource("#{wafrxssset["name"]}") do
        Type("AWS::WAF::XssMatchSet")
        Property("Name", FnJoin("-", [Ref("EnvironmentName"), wafrxssset["name"]]))
        Property("XssMatchTuples", xssmatchtuple_list )
      end

  end if defined? control_wafrxssset

  # Size constraint conditions
  control_sizeconstraintset.each do |sizeconstraintset|

    sizeconstraint_list = []
    sizeconstraintset["sizeconstraints"].each do |sizeconstraint|

      object = {}
      object[:FieldToMatch] = {}
      object[:FieldToMatch][:Type] = sizeconstraint["field_type"]
      object[:TextTransformation] = sizeconstraint["texttransformation"]
      object[:FieldToMatch][:Data] = sizeconstraint["field_data"] if sizeconstraint.has_key?("field_data")
      sizeconstraint_list << object

    end

    Resource("#{sizeconstraintset["name"]}") do
      Type("AWS::WAF::SizeConstraintSet")
      Property("Name", FnJoin("-", [Ref("EnvironmentName"), sizeconstraintset["name"]]))
      Property("SizeConstraints", sizeconstraint_list )
    end

  end if defined? control_sizeconstraintset

  control_bytematchset.each do |bytematchset|

    bytematchtuple_list = []
    bytematchset["bytematchtuples"].each do |bytematchtuple|

      object = {}
      object[:FieldToMatch] = {}
      object[:TextTransformation] = bytematchtuple["texttransformation"]
      object[:PositionalConstraint] = bytematchtuple["positionalconstraint"]
      object[:TargetString] = bytematchtuple["targetstring"]
      object[:FieldToMatch][:Type] = bytematchtuple["field_type"]
      object[:FieldToMatch][:Data] = bytematchtuple["field_data"] if bytematchtuple.has_key?("field_data")
      bytematchtuple_list << object


    end

    Resource("#{bytematchset["name"]}") do
      Type("AWS::WAF::ByteMatchSet")
      Property("Name", FnJoin("-", [Ref("EnvironmentName"), bytematchset["name"]]))
      Property("ByteMatchTuples", bytematchtuple_list )
    end

  end if defined? control_bytematchset

  control_ipset.each do |ipset|

    ipsetdescriptor_list = []
    ipset["ipsetdescriptors"].each do |ipsetdescriptor|
      ipsetdescriptor_list << {
        Type: ipsetdescriptor["type"] || "IPV4",
        Value: ipsetdescriptor["value"]
      }
    end

    Resource("#{ipset["name"]}") do
      Type("AWS::WAF::IPSet")
      Property("Name", FnJoin("-", [Ref("EnvironmentName"), ipset["name"]]))
      Property("IPSetDescriptors", ipsetdescriptor_list )
    end

  end if defined? control_ipset

  ## Create the Rules
  wafrules.each do |wafrule|
    waf_predicates = []
    wafrule["predicates"].each do |predicate|
      if predicate['type']=="RegexMatch"
         waf_predicates << {
          DataId: FnGetAtt(predicate["conditionName"],'MatchID'),
          Negated: predicate["negated"],
          Type: predicate["type"]
        }
      else
         waf_predicates << {
          DataId: Ref( "#{predicate["conditionName"]}" ),
          Negated: predicate["negated"],
          Type: predicate["type"]
        }
      end
    end

    Resource(wafrule["ruleid"]) do
      Type("AWS::WAF::Rule")
      Property("MetricName", FnJoin("", [Ref("EnvironmentName"), wafrule["ruleid"] ]))
      Property("Name", FnJoin("-", [Ref("EnvironmentName"), wafrule["ruleid"] ]))
      Property("Predicates",  waf_predicates )
    end

  end if defined? wafrules

  if defined? wafacl
    waf_rules = []
    wafacl['rules'].each do |rule|
      waf_rules << {
        Action: { Type: rule["action"] },
        Priority: rule["priority"],
        RuleId: Ref(rule["ruleid"])
      }
    end

    Resource("wafrOwaspACL") do
      Type("AWS::WAF::WebACL")
      Property("MetricName", FnJoin("", [ Ref("EnvironmentName"), wafacl['metricName'] ]))
      Property("Name", FnJoin("-", [Ref("EnvironmentName"), wafacl['name'] ]))
      Property("DefaultAction", { "Type" => "ALLOW" })
      Property("Rules", waf_rules)
    end

    Output('WAFWebACL', Ref('wafrOwaspACL'))
  end

end
