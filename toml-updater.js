const toml = require('@iarna/toml')


module.exports.readVersion = function (contents) {
    var json = toml.parse(contents);

    return  json.package.version
}

module.exports.writeVersion = function (contents, version) {
    var json = toml.parse(contents);
    json.package.version = version;

    return toml.stringify(json)
}