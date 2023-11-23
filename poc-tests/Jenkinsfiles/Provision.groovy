

String provision_path = "${WORKSPACE}/scripts/provision"
String provision_script = "provision.py"
String inventory = "inventory.yaml"
String jenkins_reference = params.getOrDefault('JENKINS_REFERENCE', 'enhancement/4665-dtt1-poc')

// Jenkinsfile

node {

  stage('Clone Repo') {
    print("Clone repository")
    git branch: "${JENKINS_REFERENCE}", url: 'https://github.com/wazuh/wazuh-qa.git'
  }

  stage('Provision') {
    print("Launch provision")
    sh "python3 ${provision_path}/${provision_script} -i ${inventory}"
  }

  post {
      always {
          sh 'deactivate || true'
          sh 'rm -rf venv'
      }
  }

}