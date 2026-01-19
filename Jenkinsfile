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
            emailext(
                subject: "✅ Jenkins Job SUCCESS: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
Hello Team,

✅ Jenkins Job completed SUCCESSFULLY.

Job Name : ${env.JOB_NAME}
Build No : ${env.BUILD_NUMBER}
Build URL: ${env.BUILD_URL}

Regards,
Jenkins
""",
                to: "p10prmar@gmail.com"
            )
        }

        failure {
            emailext(
                subject: "❌ Jenkins Job FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
Hello Team,

❌ Jenkins Job FAILED.

Job Name : ${env.JOB_NAME}
Build No : ${env.BUILD_NUMBER}
Build URL: ${env.BUILD_URL}

Please check logs.

Regards,
Jenkins
""",
                to: "p10prmar@gmail.com"
            )
        }
    }
}
