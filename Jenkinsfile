pipeline {
    agent any
    options {
        checkoutToSubdirectory('B2HANDLE')
    }
    environment {
        PROJECT_DIR="B2HANDLE"
    }
    stages {
        stage ('Run tests for each python version') {
            parallel {
                stage ('Test python 2.7') {
                    agent {
                        dockerfile {
                            filename "b2handle/tests/Dockerfile"
                            dir "$PROJECT_DIR"
                            additionalBuildArgs "-t eudat-b2handle"
                            args "-u root:root"
                        }
                    }
                    steps {
                        sh '''
                            cd $WORKSPACE/$PROJECT_DIR/b2handle/tests
                            ./docker-entrypoint.sh coverage
                        '''
                        cobertura coberturaReportFile: '**/coverage.xml'
                    }
                }
                stage ('Test python 3.5') {
                    agent {
                        dockerfile {
                            filename "b2handle/tests/Dockerfile-py3.5"
                            dir "$PROJECT_DIR"
                            additionalBuildArgs "-t eudat-b2handle:py3.5"
                            args "-u root:root"
                        }
                    }
                    steps {
                        sh '''
                            cd $WORKSPACE/$PROJECT_DIR/b2handle/tests
                            ./docker-entrypoint.sh coverage
                        '''
                        cobertura coberturaReportFile: '**/coverage.xml'
                    }
                }
                stage ('Test python 3.6') {
                    agent {
                        dockerfile {
                            filename "b2handle/tests/Dockerfile-py3.6"
                            dir "$PROJECT_DIR"
                            additionalBuildArgs "-t eudat-b2handle:py3.6"
                            args "-u root:root"
                        }
                    }
                    steps {
                        sh '''
                            cd $WORKSPACE/$PROJECT_DIR/b2handle/tests
                            ./docker-entrypoint.sh coverage
                        '''
                        cobertura coberturaReportFile: '**/coverage.xml'
                    }
                }
                stage ('Test python 3.7') {
                    agent {
                        dockerfile {
                            filename "b2handle/tests/Dockerfile-py3.7"
                            dir "$PROJECT_DIR"
                            additionalBuildArgs "-t eudat-b2handle:py3.7"
                            args "-u root:root"
                        }
                    }
                    steps {
                        sh '''
                            cd $WORKSPACE/$PROJECT_DIR/b2handle/tests
                            ./docker-entrypoint.sh coverage
                        '''
                        cobertura coberturaReportFile: '**/coverage.xml'
                    }
                }
            }
        }
    }
    post {
        always {
            cleanWs()
        }
    }
} 