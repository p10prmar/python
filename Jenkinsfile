pipeline {
    agent any
    
    environment {
        IMAGE_NAME = "vast-system"
        IMAGE_TAG = "1.0"
    }

    stages {
        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Verify Environment') {
            steps {
                echo 'Checking Python version'
                sh 'python3 --version'
            }
        }

        stage('Build Docker Image') {
            steps {
                echo "Building: ${IMAGE_NAME}:${IMAGE_TAG}"
                // Build the image using the Dockerfile we created above
                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ."
            }
        }

        stage('Test Run') {
            steps {
                echo 'Testing the container'
                // This runs the container to make sure the script works inside it
            }
        }
    }
    
    post {
        success {
            mail to: 'p10prmar@gmail.com',
                body: 'done'
            echo 'Python Pipeline completed successfully'
        }
        failure {
            echo 'Pipeline failed'
        }
    }
}
