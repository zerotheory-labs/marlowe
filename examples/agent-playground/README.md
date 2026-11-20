# Benjamin local model playground

A disposable, dependency-free project for a real-model Agent-mode smoke test.

Ask Benjamin to read the files, add a test for a missing name, update greet so
an omitted name returns "Hello, friend!", and run `node --test greeting.test.cjs`.
The test command should pause for approval. Review it, then approve it once.

In a separate message, ask Benjamin to delete `obsolete-note.txt` using the
file tool. First deny the proposal and verify the file remains. Ask again,
approve the deletion, and use Undo file change to restore it after the run.

## Live test result — November 17, 2026

Tested with the installed Ollama `qwen3-vl:8b-instruct` model through Benjamin's
production agent engine. The model updated the greeting and added a missing-name
test; both tests passed after approval of the test command. A duplicate export
introduced by the model was corrected through an approved cleanup. The model
then proposed deleting the disposable note, waited for approval, and deleted it.
Benjamin's backup restore recovered the exact original bytes.

The first attempt encountered a local HTTP 500; a resumed run completed. Desktop
screen capture was unavailable, so this live test used the engine and approval
gate directly, with the user's decisions relayed from chat. The desktop approval
UI was not exercised against the live model in this test.

Connection saved in Benjamin: `http://127.0.0.1:11434/v1`, model
`qwen3-vl:8b-instruct`, no API key. Restart Benjamin to load the saved connection.
Choose this folder in Agent mode to experiment further. Local test logs and the
verification record are under the repository's ignored `.live-agent/` directory.
