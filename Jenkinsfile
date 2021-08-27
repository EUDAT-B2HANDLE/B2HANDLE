pipeline {
    agent any
    options {
        checkoutToSubdirectory('B2HANDLE')
    }
    environment {
        PROJECT_DIR="B2HANDLE"
    }
    stages {
        stage ('Test python 2.7') {
            agent {
                dockerfile {
                    filename "b2handle/tests/Dockerfile"
                    dir "$PROJECT_DIR"
                }
            }
            steps {
                sh '''
                    cd /opt/B2HANDLE/b2handle/tests
                    ./docker-entrypoint.sh coverage
                '''
            }
        }
        stage ('Test python 3.5') {
            agent {
                dockerfile {
                    filename "b2handle/tests/Dockerfile-py3.5"
                    dir "$PROJECT_DIR"
                }
            }
            steps {
                sh '''
                    cd /opt/B2HANDLE/b2handle/tests
                    ./docker-entrypoint.sh coverage
                '''
            }
        }
        stage ('Test python 3.6') {
            agent {
                dockerfile {
                    filename "b2handle/tests/Dockerfile-py3.6"
                    dir "$PROJECT_DIR"
                }
            }
            steps {
                sh '''
                    cd /opt/B2HANDLE/b2handle/tests
                    ./docker-entrypoint.sh coverage
                '''
            }
        }
        stage ('Test python 3.7') {
            agent {
                dockerfile {
                    filename "b2handle/tests/Dockerfile-py3.7"
                    dir "$PROJECT_DIR"
                }
            }
            steps {
                sh '''
                    cd /opt/B2HANDLE/b2handle/tests
                    ./docker-entrypoint.sh coverage
                '''
            }
        }
    }
    post {
        always {
            cleanWs()
        }
    }
} 