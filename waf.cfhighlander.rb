HighlanderComponent do
  DependsOn 'vpc@1.0.4'

  Description "#{component_name} - #{component_version}"

  Parameters do
    StackParam 'EnvironmentName', 'dev', isGlobal: true
    StackParam 'EnvironmentType', 'development', isGlobal: true
  end



end
