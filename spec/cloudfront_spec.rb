require 'yaml'

describe 'cloudfront waf configuration' do
  
  context 'cftest' do
    it 'compiles test' do
      expect(system("cfhighlander cftest #{@validate} --tests tests/cloudfront.test.yaml")).to be_truthy
    end
  end
  
  let(:template) { YAML.load_file("#{File.dirname(__FILE__)}/../out/tests/cloudfront/waf.compiled.yaml") }
  
  context 'Resource WebACL' do
    let(:properties) { template["Resources"]["WebACL"]["Properties"] }

    it 'has basic properties' do
      expect(properties["Name"]).to eq({"Fn::Sub"=>"${EnvironmentName}-test-cloudfront-waf"})
      expect(properties["Description"]).to eq("Test CloudFront WAF ACL")
      expect(properties["Scope"]).to eq("CLOUDFRONT")
      expect(properties["DefaultAction"]).to eq({"Allow"=>{}})
    end

    it 'has rules configured' do
      rules = properties["Rules"]
      expect(rules.length).to eq(2)

      # Geo Block Rule
      geo_rule = rules.find { |r| r["Name"] == "geo-block" }
      expect(geo_rule["Priority"]).to eq(1)
      expect(geo_rule["Action"]).to eq({"Block"=>{}})
      expect(geo_rule["Statement"]["GeoMatchStatement"]["CountryCodes"]).to include("CN", "RU", "KP")

      # XSS Protection Rule
      xss_rule = rules.find { |r| r["Name"] == "xss-protection" }
      expect(xss_rule["Priority"]).to eq(2)
      expect(xss_rule["Action"]).to eq({"Block"=>{}})
      expect(xss_rule["Statement"]["XssMatchStatement"]["FieldToMatch"]).to eq({"Body"=>{}})
      expect(xss_rule["Statement"]["XssMatchStatement"]["TextTransformations"]).to include(
        {"Priority"=>1, "Type"=>"NONE"}
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
