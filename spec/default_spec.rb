require 'yaml'

describe 'default waf configuration' do
  
  context 'cftest' do
    it 'compiles test' do
      expect(system("cfhighlander cftest #{@validate} --tests tests/default.test.yaml")).to be_truthy
    end
  end
  
  let(:template) { YAML.load_file("#{File.dirname(__FILE__)}/../out/tests/default/waf.compiled.yaml") }
  
  context 'Resource WebACL' do
    let(:properties) { template["Resources"]["WebACL"]["Properties"] }

    it 'has basic properties' do
      expect(properties["Name"]).to eq({"Fn::Sub"=>"${EnvironmentName}-test-waf"})
      expect(properties["Description"]).to eq("Test WAF ACL")
      expect(properties["Scope"]).to eq("REGIONAL")
      expect(properties["DefaultAction"]).to eq({"Allow"=>{}})
    end

    it 'has rules configured' do
      rules = properties["Rules"]
      expect(rules.length).to eq(2)

      # IP Rate Limit Rule
      rate_rule = rules.find { |r| r["Name"] == "ip-rate-limit" }
      expect(rate_rule["Priority"]).to eq(1)
      expect(rate_rule["Action"]).to eq({"Block"=>{}})
      expect(rate_rule["Statement"]["RateBasedStatement"]["Limit"]).to eq(2000)
      expect(rate_rule["Statement"]["RateBasedStatement"]["AggregateKeyType"]).to eq("IP")

      # SQL Injection Rule
      sql_rule = rules.find { |r| r["Name"] == "sql-injection" }
      expect(sql_rule["Priority"]).to eq(2)
      expect(sql_rule["Action"]).to eq({"Block"=>{}})
      expect(sql_rule["Statement"]["SqlInjectionMatchStatement"]["FieldToMatch"]).to eq({"Body"=>{}})
      expect(sql_rule["Statement"]["SqlInjectionMatchStatement"]["TextTransformations"]).to include(
        {"Priority"=>1, "Type"=>"URL_DECODE"},
        {"Priority"=>2, "Type"=>"HTML_ENTITY_DECODE"}
      )
    end
  end

  context 'Outputs' do
    let(:outputs) { template["Outputs"] }

    it 'has web acl id' do
      expect(outputs["WebACLId"]).to include(
        "Value" => {"Ref"=>"WebACL"}
      )
    end

    it 'has web acl arn' do
      expect(outputs["WebACLArn"]).to include(
        "Value" => {"Fn::GetAtt"=>["WebACL", "Arn"]}
      )
    end
  end
end
