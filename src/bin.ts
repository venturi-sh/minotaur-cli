import { exitCodeFor, main } from './main.js';

// exitCode rather than process.exit(): exiting outright drops whatever of a
// large --json result is still buffered for a pipe.
main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: Error) => {
    process.stderr.write(`minotaur: ${error.message}\n`);
    process.exitCode = exitCodeFor(error);
  },
);
