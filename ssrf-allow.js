

const getAllowList = () => {
    if  ('EXTERNAL_YAML_URL_ALLOW_LIST' in process.env) {
        return process.env['EXTERNAL_YAML_URL_ALLOW_LIST']
    }
    if  ('EXTERNAL_YAML_URL_WHITE_LIST' in process.env) {
        return process.env['EXTERNAL_YAML_URL_WHITE_LIST']
    }
}

module.exports = { getAllowList };
