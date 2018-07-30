let cheerio = require('cheerio')

module.exports = function() {
    self = this;
    let root = null;

    self.parse = function(html) {
        const $ = cheerio.load(html, {decodeEntities: true});
        return $('title').text();
    }
}