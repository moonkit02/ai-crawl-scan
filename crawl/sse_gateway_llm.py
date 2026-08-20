"""
ChatSSEGateway: a ChatOpenAI variant for an OpenAI-compatible gateway that ALWAYS
streams Server-Sent Events (text/event-stream) and reads `max_tokens` (not
`max_completion_tokens`). browser-use's stock ChatOpenAI makes a non-streaming call,
so the SDK gets SSE where it expects JSON and fails with
"'str' object has no attribute 'choices'". This subclass:

  * calls the model with stream=True (the gateway's only mode) and reassembles content,
  * passes max_tokens via extra_body so the gateway honours the budget,
  * gets structured output by injecting the JSON schema into the prompt and parsing
    JSON out of the reply (no dependency on strict response_format support).

Tested against a MiniMax M2.5 Bedrock-gateway Lambda URL in ap-southeast-1.
"""

import json
import re
from dataclasses import dataclass
from typing import Any, TypeVar

from pydantic import BaseModel

from browser_use.llm.openai.chat import ChatOpenAI
from browser_use.llm.openai.serializer import OpenAIMessageSerializer
from browser_use.llm.messages import BaseMessage
from browser_use.llm.schema import SchemaOptimizer
from browser_use.llm.views import ChatInvokeCompletion

T = TypeVar('T', bound=BaseModel)


def _extract_json(text: str) -> str:
    """Pull the JSON object out of a reply that may have prose or ```json fences."""
    t = text.strip()
    t = re.sub(r'^```(?:json)?\s*|\s*```$', '', t, flags=re.IGNORECASE).strip()
    try:
        json.loads(t)
        return t
    except Exception:
        pass
    start, end = t.find('{'), t.rfind('}')
    if start != -1 and end > start:
        return t[start : end + 1]
    return t


@dataclass
class ChatSSEGateway(ChatOpenAI):
    max_tokens_budget: int = 16384  # gateway reads `max_tokens`; give reasoning models headroom

    @property
    def provider(self) -> str:
        return 'sse_gateway'

    async def ainvoke(  # type: ignore[override]
        self, messages: list[BaseMessage], output_format: type[T] | None = None, **kwargs: Any
    ) -> ChatInvokeCompletion:
        openai_messages = OpenAIMessageSerializer.serialize_messages(messages)

        if output_format is not None:
            schema = SchemaOptimizer.create_optimized_json_schema(output_format)
            instr = (
                '\n\nYou MUST reply with ONLY a single JSON object that validates against '
                f'this JSON schema. No prose, no markdown fences.\n<json_schema>\n{json.dumps(schema)}\n</json_schema>'
            )
            if openai_messages and openai_messages[0].get('role') == 'system' and isinstance(
                openai_messages[0].get('content'), str
            ):
                openai_messages[0]['content'] += instr
            else:
                openai_messages.insert(0, {'role': 'system', 'content': instr.strip()})

        params: dict[str, Any] = {
            'model': self.model,
            'messages': openai_messages,
            'stream': True,
            'extra_body': {'max_tokens': self.max_tokens_budget},
        }
        if self.temperature is not None:
            params['temperature'] = self.temperature

        stream = await self.get_client().chat.completions.create(**params)

        parts: list[str] = []
        finish_reason: str | None = None
        async for chunk in stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if delta and getattr(delta, 'content', None):
                parts.append(delta.content)
            if chunk.choices[0].finish_reason:
                finish_reason = chunk.choices[0].finish_reason
        content = ''.join(parts)

        if output_format is None:
            return ChatInvokeCompletion(completion=content, usage=None, stop_reason=finish_reason)

        parsed = output_format.model_validate_json(_extract_json(content))
        return ChatInvokeCompletion(completion=parsed, usage=None, stop_reason=finish_reason)
