@Library('jenkins-qa-library') _

String master_node = null

node(master_node){
  try{
    stage('STAGE 0: Initialize'){

    }

    stage('STAGE 1: Parse template'){
      Template template = new Template('/path/to/template')
    }


    stage('STAGE 2: Launch instances'){

    }


  }catch(exception){
    throw exception
  }
}
