const getAllowList = () => {
     const allowedArr = process.env['EXTERNAL_YAML_URL_ALLOW_LIST'] || process.env['EXTERNAL_YAML_URL_WHITE_LIST'] || '[]';
     console.log(`Using allowed list:'${allowedArr}'.`)
     return JSON.parse(allowedArr);
}

module.exports = { getAllowList };
