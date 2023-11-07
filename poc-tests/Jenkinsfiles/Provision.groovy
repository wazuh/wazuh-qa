

String provision_path = "scripts/provision"
String provision_script = "provisioner.py"
String inventory = "inventory.yaml"
String jenkins_reference = params.getOrDefault('JENKINS_REFERENCE', 'enhancement/4665-dtt1-poc')

// Jenkinsfile

node {

  stage('Clone Repo') {
    git branch: ${JENKINS_REFERENCE}, url: 'https://github.com/wazuh/wazuh-qa.git'
  }

  stage('Provision') {
    sh "python3 ${provision_path}/${provision_script} -i ${inventory.yaml}"
  }

}