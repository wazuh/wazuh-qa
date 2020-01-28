@Library('jenkins-shared-library@641-add-qa-templates') _

String master_node = null
String jenkins_branch = '641-add-qa-templates'
//String agent_image = 'centos-7'
//String manager_image = 'centos-7'
String target_version
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
        dir('wazuh-qa'){
          gitHelper.lightCheckout(
            branch: '94-add-tests-jenkins',
            repository: vars.DEFAULT_WAZUH_QA_REPOSITORY
          )
        }
      }

      stage('STAGE 1: Parse template'){
        info_data = readYaml(file: 'wazuh-qa/tests/info.yml')
        module_data = readYaml(file: "wazuh-qa/tests/${module}/module.yml")
        test_data = readYaml(file: "wazuh-qa/tests/${module}/${test}/test.yml")

        num_agents = test_data.number_of_agents
        num_managers = test_data.number_of_managers

        images = test_data.system_target
        target_version = test_data.maximum_supported_version
      }


      stage('STAGE 2: Generate deploy data'){
        instance.init(branch: jenkins_branch)

        images.each{ img ->
          deploy_prefix = 'B' + BUILD_NUMBER + '_' + img + '_'+ module + '_'  + test
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
            ecr_source_version: target_version
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

        hosts_config_path.each{ config_data ->
          wazuh.registerAgents(
            hosts_config_path: config_data,
            source_version: target_version,
            verbosity: verbosity
          )
        }
      }



      stage('STAGE 4: Launch test'){
        hosts_config_path.each{ config_data ->
          ansiblePlaybook(
            credentialsId: vars.DEFAULT_ANSIBLE_CREDENTIALS_ID,
            disableHostKeyChecking: vars.DISABLE_HOST_KEY_CHECKING,
            extraVars: [
              src_folder: "../tests/${module}/${test}",
              dest_folder: 'tests'
            ],
            inventory: config_data,
            playbook: "wazuh-qa/ansible/transfer_files.yml",
            extras: verbosity,
            colorized: vars.COLORIZED_ANSIBLE
          )

          test_data.tests.each{ test_object ->

            echo 'Test: ' + test_object.toString()
            test_object.value.agents.each{ agent ->
              echo 'Agent: ' + agent.toString()
              agent.value.each{ item ->
                  ansiblePlaybook(
                    credentialsId: vars.DEFAULT_ANSIBLE_CREDENTIALS_ID,
                    disableHostKeyChecking: vars.DISABLE_HOST_KEY_CHECKING,
                    extraVars: [
                      binary: 'python',
                      script: "/tests/${test_object.key}/${item.value}"
                    ],
                    limit: 'Agents',
                    inventory: config_data,
                    playbook: "wazuh-qa/ansible/launch_script.yml",
                    extras: verbosity,
                    colorized: vars.COLORIZED_ANSIBLE
                  )
                  echo 'Item.key: ' + item.key.toString()
                  echo 'Item.value: ' + item.value.toString()
              }
            }

            echo 'Test: ' + test_object.toString()
            test_object.value.managers.each{ manager ->
              echo 'Manager: ' + manager.toString()
              manager.value.each{ item ->
                  ansiblePlaybook(
                    credentialsId: vars.DEFAULT_ANSIBLE_CREDENTIALS_ID,
                    disableHostKeyChecking: vars.DISABLE_HOST_KEY_CHECKING,
                    extraVars: [
                      binary: 'python',
                      script: "/tests/${test_object.key}/${item.value}"
                    ],
                    limit: 'Managers',
                    inventory: config_data,
                    playbook: "wazuh-qa/ansible/launch_script.yml",
                    extras: verbosity,
                    colorized: vars.COLORIZED_ANSIBLE
                  )
                  echo 'Item.key: ' + item.key.toString()
                  echo 'Item.value: ' + item.value.toString()
              }
            }
          }
        }
      }



    }

  }catch(exception){
    throw exception
  }
}
