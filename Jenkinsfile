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
    // Gets the 2nd commit, because the first one will be a 'Merge pull request...'
    // commit resulting from the merge to master.
    shortCommitHash = sh(
        returnStdout: true,
        script: "git log -n 2 --pretty=format:'%h' | tail -n 1").trim()
    message = sh(
        returnStdout: true,
        script: "git log --format=%B -n 1 ${shortCommitHash}").trim()
    return message.startsWith("Version change")
}
