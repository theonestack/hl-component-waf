CfhighlanderTemplate do

  Description "#{component_name} - #{component_version}"

  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', isGlobal: true
    ComponentParam 'AssociatedResourceArn', ''
  end

  LambdaFunctions 'custom_resource_functions' if defined? custom_resource_functions

end
