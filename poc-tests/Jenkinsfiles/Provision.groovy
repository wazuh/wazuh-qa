

String provision_path = "scripts/provision"
String provision_script = "provisioner.py"
String inventory = "inventory.yaml"

// Jenkinsfile

node {

  stage('Clone Repo') {
    git branch: 'enhancement/4524-dtt1-poc', url: 'https://github.com/wazuh/wazuh-qa.git'
  }

  stage('Provision') {
    sh "python3 ${provision_path}/${provision_script} -i ${inventory.yaml}"
  }

}