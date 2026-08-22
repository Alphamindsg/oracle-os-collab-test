# Claude GitHub Collaboration Test

Purpose: verify what GitHub operations Claude can actually perform on this public sandbox repository.

## Task

1. Read `README.md` and `sample.py`.
2. Create a new branch named `claude-collab-test`.
3. Add a new file named `CLAUDE_RESULT.md` that:
   - confirms which GitHub operations were available;
   - explains what `sample.py` currently does;
   - describes one small improvement you chose to make.
4. Improve `sample.py` in a small, safe way. Keep the existing `greet(name: str) -> str` behavior compatible for normal non-empty names.
5. Add `test_sample.py` using Python's built-in `unittest` framework. Include tests for the original normal-name behavior and for your improvement.
6. Run the tests if your environment supports execution. Record the exact test command and result in `CLAUDE_RESULT.md`.
7. Commit the changes to `claude-collab-test`.
8. Open a pull request from `claude-collab-test` to `main` titled `Claude collaboration capability test`.
9. Do not modify any other files.

## Stop conditions

If any requested operation is unsupported, stop at that point and report exactly what you could and could not do. Do not claim success for an operation you could not verify.

## Safety boundary

This is only a public capability test. Do not request, copy, or infer any private Oracle OS source code, secrets, customer data, research-library material, or proprietary knowledge.
