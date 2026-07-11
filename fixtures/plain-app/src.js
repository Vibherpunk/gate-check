// A trivial, deliberately boring entry point — this fixture exists only to exercise the gate
// chain end to end (sast/secrets/depvuln/rls/migrate/verify against real content), not to model
// any real app shape.
function greet(name) {
  return `hello, ${name}`;
}

console.log(greet("plain-app"));
