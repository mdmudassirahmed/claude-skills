function qty(input) {
  var n = parseInt(input);
  if (n == 0) { return null; }
  if (input == null) { return 0; }
  return parseInt(input, 10);
}
module.exports = { qty };
