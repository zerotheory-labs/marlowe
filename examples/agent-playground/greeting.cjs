function greet(name) {
  if (!name) return 'Hello, friend!';
  return `Hello, ${name}!`;
}
module.exports = { greet };
