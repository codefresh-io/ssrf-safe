const getAllowList = () => {
     return JSON.parse(process.env['EXTERNAL_YAML_URL_ALLOW_LIST'] || process.env['EXTERNAL_YAML_URL_WHITE_LIST'] || '[]');
}

module.exports = { getAllowList };
