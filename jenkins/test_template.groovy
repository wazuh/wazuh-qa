@Library('jenkins-qa-library') _
@Library('jenkins-shared-library@641-add-qa-templates') _
import org.wazuh.Template

String master_node = null

node(master_node){
  try{
    stage('STAGE 0: Initialize'){
      gitHelper.lightCheckout(
        branch: '94-add-tests-jenkins',
        repository: vars.DEFAULT_WAZUH_QA_REPOSITORY
      )
    }

    stage('STAGE 1: Parse template'){
      Template template = new Template('tests/specification.yml')
      echo template.data.toString()
    }


    stage('STAGE 2: Launch instances'){

    }


  }catch(exception){
    throw exception
  }
}
