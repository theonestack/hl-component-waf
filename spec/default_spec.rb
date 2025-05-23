require 'yaml'

describe 'default waf configuration' do
  
  context 'cftest' do
    it 'compiles test' do
      expect(system("cfhighlander cftest #{@validate} --tests tests/default.test.yaml")).to be_truthy
    end
  end
  
  let(:template) { YAML.load_file("#{File.dirname(__FILE__)}/../out/tests/default/waf.compiled.yaml") }
  
  context 'Resources' do
    let(:resources) { template["Resources"] }

    context 'IPSet' do
      let(:properties) { resources["wafrBlacklistIpSet"]["Properties"] }

      it 'has basic properties' do
        expect(properties["Name"]).to eq({"Fn::Join"=>["-", [{"Ref"=>"EnvironmentName"}, "wafrBlacklistIpSet"]]})
        expect(properties["IPSetDescriptors"]).to include(
          {"Type"=>"IPV4", "Value"=>"192.0.2.44/32"}
        )
      end
    end

    context 'Rule' do
      let(:properties) { resources["wafrIPBlockRule"]["Properties"] }

      it 'has basic properties' do
        expect(properties["Name"]).to eq({"Fn::Join"=>["-", [{"Ref"=>"EnvironmentName"}, "wafrIPBlockRule"]]})
        expect(properties["MetricName"]).to eq({"Fn::Join"=>["", [{"Ref"=>"EnvironmentName"}, "wafrIPBlockRule"]]})
      end

      it 'has predicates configured' do
        expect(properties["Predicates"]).to include(
          {
            "DataId"=>{"Ref"=>"wafrBlacklistIpSet"},
            "Negated"=>false,
            "Type"=>"IPMatch"
          }
        )
      end
    end

    context 'WebACL' do
      let(:properties) { resources["wafrOwaspACL"]["Properties"] }

      it 'has basic properties' do
        expect(properties["Name"]).to eq({"Fn::Join"=>["-", [{"Ref"=>"EnvironmentName"}, "test-waf"]]})
        expect(properties["MetricName"]).to eq({"Fn::Join"=>["", [{"Ref"=>"EnvironmentName"}, "TestWAF"]]})
        expect(properties["DefaultAction"]).to eq({"Type"=>"ALLOW"})
      end

      it 'has rules configured' do
        expect(properties["Rules"]).to include(
          {
            "Action"=>{"Type"=>"BLOCK"},
            "Priority"=>1,
            "RuleId"=>{"Ref"=>"wafrIPBlockRule"}
          }
        )
      end
    end
  end

  context 'Outputs' do
    let(:outputs) { template["Outputs"] }

    it 'has web acl id' do
      expect(outputs["WAFWebACL"]).to eq({"Value"=>{"Ref"=>"wafrOwaspACL"}})
    end
  end
end
