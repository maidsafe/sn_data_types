stage('build & test') {
    parallel mock_linux: {
        node('safe_nd') {
            checkout(scm)
            sh("make test")
        }
    },
    windows: {
        node('windows') {
            checkout(scm)
            sh("make test")
        }
    },
    osx: {
        node('osx') {
            checkout(scm)
            sh("make test")
        }
    }
}

stage('deploy') {
    node('safe_nd') {
        checkout(scm)
        if (env.BRANCH_NAME == "master") {
            if (versionChangeCommit()) {
                withCredentials([string(
                    credentialsId: 'crates_io_token', variable: 'CRATES_IO_TOKEN')]) {
                    sh("make publish")
                }
            }
        } else {
            echo("${env.BRANCH_NAME} does not match deployment branch. Nothing to do.")
        }
    }
}

def versionChangeCommit() {
    shortCommitHash = sh(
        returnStdout: true,
        script: "git log -n 1 --pretty=format:'%h'").trim()
    message = sh(
        returnStdout: true,
        script: "git log --format=%B -n 1 ${shortCommitHash}").trim()
    return message.startsWith("Version change")
}
