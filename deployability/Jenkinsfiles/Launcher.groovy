String jenkins_reference = params.getOrDefault('JENKINS_REFERENCE', 'enhancement/4751-dtt1-iteration-2-poc')
String launcher_path = "modules/provision"
String task_flow_launcher = "main.py"
String workflow = "modules/workflow_engine/examples/dtt1-managers.yaml"
String schema = "modules/workflow_engine/schema.json"

// Jenkinsfile

node {

  try {
    stage('Clone Repo') {
      print("Clone repository")
      git branch: "${JENKINS_REFERENCE}", url: 'https://github.com/wazuh/wazuh-qa.git'
    }

    stage('Launch Task Flow') {
      print("Launch Task Flow dry run")
      sh "cd ${env.WORKSPACE}/deployability && python3 ${launcher_path}/${task_flow_launcher} ${workflow} --dry-run"

      print("Launch Task Flow")
      sh "cd ${env.WORKSPACE}/deployability && python3 ${launcher_path}/${task_flow_launcher} ${workflow} ${schema}"
    }
  }
  finally{
    stage('Remove venv') {
      sh "rm -rf ${env.WORKSPACE}/deployability/venv"
    }
  }
}