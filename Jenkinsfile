pipeline {
    agent any

    environment {
        IMAGE_NAME = "vast-system"
        IMAGE_TAG  = "1.0"
        MAIL_TO    = "p.10prmar@gmail.com"
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
                echo "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"
                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ."
            }
        }

        stage('Test Run') {
            steps {
                echo 'Testing the container'
                // Example test run (optional)
                // sh "docker run --rm ${IMAGE_NAME}:${IMAGE_TAG}"
            }
        }
    }

    post {

        success {
            emailext(
                to: env.MAIL_TO,
                subject: "✅ SUCCESS | ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                mimeType: 'text/html',
                body: """
                <h2 style="color:green;">Jenkins Build Successful ✅</h2>
                <p><b>Job Name:</b> ${env.JOB_NAME}</p>
                <p><b>Build Number:</b> ${env.BUILD_NUMBER}</p>
                <p><b>Docker Image:</b> ${IMAGE_NAME}:${IMAGE_TAG}</p>
                <p><b>Status:</b> SUCCESS</p>
                <p>
                    <a href="${env.BUILD_URL}">
                        👉 View Build Details
                    </a>
                </p>
                <br>
                <p>Regards,<br><b>Jenkins</b></p>
                """
            )
        }

        failure {
            emailext(
                to: env.MAIL_TO,
                subject: "❌ FAILED | ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                mimeType: 'text/html',
                body: """
                <h2 style="color:red;">Jenkins Build Failed ❌</h2>
                <p><b>Job Name:</b> ${env.JOB_NAME}</p>
                <p><b>Build Number:</b> ${env.BUILD_NUMBER}</p>
                <p><b>Status:</b> FAILED</p>
                <p>
                    <a href="${env.BUILD_URL}">
                        👉 Check Failure Logs
                    </a>
                </p>
                <br>
                <p>Please investigate the issue.</p>
                <p>Regards,<br><b>Jenkins</b></p>
                """
            )
        }
    }
}
