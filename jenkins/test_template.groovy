@Library('jenkins-shared-library@641-add-qa-templates') _

String master_node = null
String jenkins_branch = '641-add-qa-templates'
//String agent_image = 'centos-7'
//String manager_image = 'centos-7'
String [] images
String num_agents
String num_managers
String deploy_node = 'Node0'
String deploy_prefix
String verbosity = '-vvv'

String module = params.MODULE
String test = params.TEST

List hosts_deploy_path = []
List hosts_config_path = []

Map info_data, module_data, test_data

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
        info_data = readYaml(file: 'tests/info.yml')
        module_data = readYaml(file: "tests/${module}/module.yml")
        test_data = readYaml(file: "tests/${module}/${test}/test.yml")

        num_agents = test_data.number_of_agents
        num_managers = test_data.number_of_managers

        images = test_data.system_target

        deploy_prefix = 'Test_' + module + '_'  + test
      }


      stage('STAGE 2: Generate deploy data'){
        instance.init(branch: jenkins_branch)

        images.each{ img ->
          hosts_deploy_path << instance.createDeployData(
            hosts_deploy_path: instance.TMP_PATH + '/' + img + '_' + 'deploy',
            agent_image: img,
            manager_image: img,
            number_of_agents: num_agents,
            number_of_managers: num_managers,
            deploy_node: deploy_node,
            deploy_prefix: deploy_prefix,
            use_ecr: true,
            ecr_repository: instance.ECR_BASE_REPOSITORY,
            ecr_source_version: '3.9.2'
            //ecr_source_version: test_data.maximum_supported_version
          )
          hosts_config_path << instance.createConfigurationData(
            hosts_config_path: instance.TMP_PATH + '/' + img + '_' + 'config',
            deploy_prefix: deploy_prefix,
            is_centos5: false
          )

        }
      }



      stage('STAGE 3: Launch instances'){
        hosts_deploy_path.each{ deploy_data ->
          instance.deploy(
            hosts_deploy_path: deploy_data,
            verbosity: verbosity
          )
        }
      }


    }

  }catch(exception){
    throw exception
  }
}
