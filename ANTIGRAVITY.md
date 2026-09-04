# Workflow Generation Policy

1. NEVER write or edit raw n8n canvas `.json` files directly.
2. When the user requests an n8n workflow:
   - Translate the request into the intermediate pipeline DSL format.
   - Save the DSL payload to `workflow_spec.json`.
   - Run the compiler via the terminal: `python compiler.py workflow_spec.json --out output_n8n.json`.
   - Verify that the compiler exited with return code 0 and generated valid JSON.
   - Present the compiled workflow path and summary to the user.
