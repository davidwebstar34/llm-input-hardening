# Demo Playground

This repository includes a runnable playground at `demo/playground.py` to visualize obfuscation removal.

```bash
uv run --extra web python -m demo.playground
```

Then open:

- `http://127.0.0.1:8000`

The UI shows:
- original text
- sanitized output
- full structured report with reason codes

This can be deployed publicly as a lightweight FastAPI app.
