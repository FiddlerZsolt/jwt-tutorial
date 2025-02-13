const morgan = require('morgan');
const chalk = require('chalk');

// Create a custom token for morgan
// morgan.token('custom', (req) => {
//   if (req.originalUrl === '/protected') {
//     return 'Accessing a protected endpoint';
//   }
//   return '';
// });

const formatter = function (tokens, req, res) {
  return [
    chalk.black.bgWhite(`[${new Date().toISOString()}]`),
    chalk.bold(`${tokens.method(req, res)} ${tokens.url(req, res)}`),
    '|',
    tokens.status(req, res),
    '|',
    tokens['response-time'](req, res),
    'ms',
  ].join(' ');
};

module.exports = morgan(formatter);
