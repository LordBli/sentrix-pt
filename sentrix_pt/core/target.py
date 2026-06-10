"""
SENTRIX-PT — Target Connector
Handles HTTP communication with the target LLM API.

Built by WREN — SENTRIX Engineering
"""

import httpx
from .engine import Target


async def send_prompt(target: Target, prompt: str) -> dict:
    """
    Send a prompt to the target LLM and return the response.

    Args:
        target: Target configuration
        prompt: The prompt to send

    Returns:
        dict with keys: content (str), raw (dict), error (str|None)
    """
    payload = {
        "model": target.model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": target.max_tokens,
    }

    headers = {
        "Authorization": f"Bearer {target.api_key}",
        "Content-Type": "application/json",
        **target.extra_headers,
    }

    try:
        async with httpx.AsyncClient(timeout=target.timeout) as client:
            response = await client.post(
                target.api_url,
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()

            # Extract content — supports OpenAI-compatible APIs
            content = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )

            return {"content": content, "raw": data, "error": None}

    except httpx.TimeoutException:
        return {"content": "", "raw": {}, "error": "TIMEOUT"}

    except httpx.HTTPStatusError as e:
        return {"content": "", "raw": {}, "error": f"HTTP_{e.response.status_code}"}

    except Exception as e:
        return {"content": "", "raw": {}, "error": str(e)}
