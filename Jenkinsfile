stage('build & test') {
    parallel mock_linux: {
        node('docker') {
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
