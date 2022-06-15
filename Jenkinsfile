pipeline {
    agent any
    options {
        checkoutToSubdirectory('B2HANDLE')
    }
    environment {
        PROJECT_DIR="B2HANDLE"
        GH_USER = 'newgrnetci'
        GH_EMAIL = '<argo@grnet.gr>'
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
                stage ('Test python 3.9') {
                    agent {
                        dockerfile {
                            filename "b2handle/tests/Dockerfile-py3.9"
                            dir "$PROJECT_DIR"
                            additionalBuildArgs "-t eudat-b2handle:py3.9"
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
        stage ('Deploy Docs') {
            when {
                changeset 'docs/**'
            }
            agent {
                docker {
                    image 'python:3.7'
                    args "-u root:root"
                }
            }
            steps {
                echo 'Building docs...'
                sh '''
                    cd $WORKSPACE/$PROJECT_DIR
                    pip install sphinx
                    python setup.py build_sphinx
                '''
                dir ("${WORKSPACE}/b2handle-pages") {
                    git branch: "gh-pages",
                        credentialsId: 'jenkins-master',
                        url: "git@github.com:EUDAT-B2SAFE/B2HANDLE.git"
                    sh """
                        cd ${WORKSPACE}/b2handle-pages
                        cp -R $WORKSPACE/$PROJECT_DIR/docs/build/html/* .
                        git add .
                        git config --global user.email ${GH_EMAIL}
                        git config --global user.name ${GH_USER}
                        git commit -m 'Update docs'
                        git push origin gh-pages
                    """
                    deleteDir()
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
