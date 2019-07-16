@Library('jenkins-shared-library@641-add-qa-templates') _

String master_node = null
String jenkins_branch = '641-add-qa-templates'
String agent_image = 'centos-7'
String manager_image = 'centos-7'
String num_agents = '1'
String num_managers = '1'
String deploy_node = 'Node0'
String deploy_prefix = 'test'
String  max_manager_version = '3.9.2'
String verbosity = '-vvv'

String hosts_deploy_path
String hosts_config_path

Map info, module, test

node(master_node){
  try{
    ansiColor(vars.DEFAULT_TERMINAL_COLOR){
      stage('STAGE 0: Initialize'){
        gitHelper.lightCheckout(
          branch: '94-add-tests-jenkins',
          repository: vars.DEFAULT_WAZUH_QA_REPOSITORY
        )
      }

      stage('STAGE 1: Parse template'){
        info = readYaml(file: 'tests/info.yml')
        module = readYaml(file: "tests/${info.available_modules[0]}/module.yml")
        test = readYaml(file: "tests/${info.available_modules[0]}/${module.available_tests[4]}/test.yml")



      }


      stage('STAGE 2: Launch instances'){
        instance.init(branch: jenkins_branch)

        hosts_deploy_path = instance.createDeployData(
          agent_image: agent_image,
          manager_image: manager_image,
          number_of_agents: template.total_agents,
          number_of_managers: template.total_managers,
          deploy_node: deploy_node,
          deploy_prefix: deploy_prefix,
          use_ecr: true,
          ecr_repository: instance.ECR_BASE_REPOSITORY,
          ecr_source_version: max_manager_version
        )

        hosts_config_path = instance.createConfigurationData(
          deploy_prefix: deploy_prefix,
          is_centos5: false
        )

        instance.deploy(verbosity: verbosity)
      }
    }

  }catch(exception){
    throw exception
  }
}
