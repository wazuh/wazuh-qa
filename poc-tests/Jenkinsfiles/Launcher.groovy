

String script_path = "${env.WORKSPACE}/scripts"
String provision_script = "provision.py"
String test_script = "test.py"
String inventory = "inventory.yaml"
String jenkins_reference = params.getOrDefault('JENKINS_REFERENCE', 'enhancement/4665-dtt1-poc')

// Jenkinsfile

node {

  try {
    stage('Clone Repo') {
      print("Clone repository")
      git branch: "${JENKINS_REFERENCE}", url: 'https://github.com/wazuh/wazuh-qa.git'
    }

    stage('Provision') {
      print("Launch provision")
      sh "cd ${env.WORKSPACE}/poc-tests && python3 ${script_path}/${provision_script} -i ${inventory}"
    }

    stage('Test') {
      print("Launch tests")
      sh "cd ${env.WORKSPACE}/poc-tests && python3 ${script_path}/${test_script} -i ${inventory} -v 4.7.0 -r 40704"
    }
  }
  finally{
    stage('Remove venv') {
      sh "rm -rf ${env.WORKSPACE}/poc-tests/venv"
    }
  }
}