pipeline {
    agent any

    stages {
        stage('Run Scan') {
            steps {
                sh 'python3 new4.py scan.py'
            }
        }

        stage('Generate Report') {
            steps {
                sh 'python3 report.py'
            }
        }
    }

    post {
        success {
            emailext(
                subject: "✅ Scan Successful - Report Attached",
                body: "Scan completed successfully. Please find the report attached.",
                to: "p10prmar@gmail.com",
                attachmentsPattern: "reports/*.html"
            )
        }

        failure {
            emailext(
                subject: "❌ Scan Failed",
                body: "Scan failed. Please check Jenkins console output.",
                to: "p10prmar@gmail.com"
            )
        }
    }
}
