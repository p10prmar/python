pipeline {
    agent any

    stages {
        stage('Run Scan') {
            steps {
                sh 'new4.py scan.py'
            }
        }

        stage('Generate Report') {
            steps {
                sh 'new4.py report.py'
            }
        }
    }

    // 👇 EMAIL GOES HERE
    post {
        success {
            emailext(
                subject: "✅ Build Success - VAPT Report",
                body: "Scan completed successfully. Report attached.",
                to: "p10prmar@gmail.com",
                attachmentsPattern: "reports/report.html"
            )
        }

        failure {
            emailext(
                subject: "❌ Build Failed",
                body: "Build failed. Check Jenkins console output.",
                to: "p10prmar@gmail.com"
            )
        }
    }
}
