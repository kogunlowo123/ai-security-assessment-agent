"""Unit tests for the graph engine, providers, retry and logging."""

from __future__ import annotations

import json
import logging
import sys

import httpx
import pytest
from pydantic import SecretStr

from aisa.errors import GraphError, ProviderError, TransientProviderError
from aisa.graph import END, WorkflowGraph
from aisa.logging_setup import JsonFormatter, configure_logging, get_logger
from aisa.providers import AnthropicChatClient, OpenAIChatClient
from aisa.retry import call_with_retry
from tests.conftest import json_client

KEY = SecretStr("sk-test-key-000000000000000000")


class TestGraph:
    def _graph(self) -> WorkflowGraph[list[str]]:
        graph: WorkflowGraph[list[str]] = WorkflowGraph()
        for name in "abc":
            graph.add_node(name, lambda s, n=name: [*s, n])
        graph.set_entry("a")
        return graph

    def test_linear_and_conditional(self) -> None:
        graph = self._graph()
        graph.add_conditional_edges("a", lambda s: "b")
        graph.add_edge("b", END)
        assert graph.run([]) == ["a", "b"]

    def test_step_budget(self) -> None:
        graph = self._graph()
        graph.add_edge("a", "a")
        with pytest.raises(GraphError, match="exceeded"):
            graph.run([], max_steps=3)

    def test_validation_errors(self) -> None:
        with pytest.raises(GraphError, match="entry"):
            WorkflowGraph[list[str]]().validate()
        graph = self._graph()
        graph.add_edge("a", "missing")
        with pytest.raises(GraphError, match="unknown node"):
            graph.validate()
        graph = self._graph()
        with pytest.raises(GraphError, match="no outgoing"):
            graph.run([])
        with pytest.raises(GraphError):
            graph.add_node("a", lambda s: s)
        with pytest.raises(GraphError):
            graph.add_node(END, lambda s: s)
        graph.add_edge("ghost", "a")
        with pytest.raises(GraphError, match="unknown node"):
            graph.validate()
        graph = self._graph()
        graph.add_conditional_edges("ghost", lambda s: END)
        with pytest.raises(GraphError, match="unknown node"):
            graph.validate()
        graph = self._graph()
        graph.add_conditional_edges("a", lambda s: "nowhere")
        with pytest.raises(GraphError, match="unknown node"):
            graph.run([])


class TestHttpAndProviders:
    def test_retries_then_succeeds(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(503) if calls["n"] < 2 else httpx.Response(200, json={"ok": 1})

        assert json_client(handler).request("GET", "http://x") == {"ok": 1}

    def test_error_mapping_and_redaction(self) -> None:
        with pytest.raises(TransientProviderError):
            json_client(lambda r: httpx.Response(429)).request("GET", "http://x")
        with pytest.raises(ProviderError) as info:
            json_client(lambda r: httpx.Response(400, text="key sk-" + "z" * 30)).request(
                "GET", "http://x"
            )
        assert "z" * 30 not in str(info.value)
        with pytest.raises(ProviderError, match="non-JSON"):
            json_client(lambda r: httpx.Response(200, text="<html>")).request("GET", "http://x")

        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route")

        with pytest.raises(TransientProviderError, match="transport"):
            json_client(boom).request("GET", "http://x")

    def test_openai_and_anthropic_clients(self) -> None:
        def openai(request: httpx.Request) -> httpx.Response:
            assert request.headers["authorization"] == f"Bearer {KEY.get_secret_value()}"
            return httpx.Response(200, json={"choices": [{"message": {"content": " hi "}}]})

        def anthropic(request: httpx.Request) -> httpx.Response:
            assert request.headers["x-api-key"] == KEY.get_secret_value()
            body = json.loads(request.content)
            assert body["system"] == "s" and body["messages"][0]["content"] == "u"
            return httpx.Response(200, json={"content": [{"type": "text", "text": "yo"}]})

        assert (
            OpenAIChatClient(json_client(openai), api_key=KEY, model="m").complete("s", "u") == "hi"
        )
        assert (
            AnthropicChatClient(json_client(anthropic), api_key=KEY, model="m").complete("s", "u")
            == "yo"
        )

    def test_bad_response_shapes(self) -> None:
        empty = json_client(lambda r: httpx.Response(200, json={}))
        with pytest.raises(ProviderError):
            OpenAIChatClient(empty, api_key=KEY, model="m").complete("s", "u")
        with pytest.raises(ProviderError):
            AnthropicChatClient(empty, api_key=KEY, model="m").complete("s", "u")
        no_text = json_client(
            lambda r: httpx.Response(200, json={"content": [{"type": "tool_use"}]})
        )
        with pytest.raises(ProviderError, match="no text"):
            AnthropicChatClient(no_text, api_key=KEY, model="m").complete("s", "u")

    def test_retry_returns_value(self) -> None:
        assert call_with_retry(lambda: 7, attempts=2, min_wait=0, max_wait=0) == 7


class TestLogging:
    def test_json_formatter_redacts(self) -> None:
        record = logging.LogRecord(
            "aisa.t", logging.INFO, __file__, 1, "tok sk-" + "q" * 30, (), None
        )
        record.tenant = "acme"
        record.note = "Bearer " + "x" * 24
        payload = json.loads(JsonFormatter().format(record))
        assert payload["message"] == "tok [REDACTED]" and payload["note"] == "[REDACTED]"
        assert payload["tenant"] == "acme"

    def test_exception_is_redacted(self) -> None:
        try:
            raise ValueError("key sk-" + "w" * 30)
        except ValueError:
            record = logging.LogRecord(
                "aisa", logging.ERROR, __file__, 1, "boom", (), sys.exc_info()
            )
        assert "w" * 30 not in json.loads(JsonFormatter().format(record))["exception"]

    def test_configure_idempotent_text_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        configure_logging("INFO", json_output=False)
        configure_logging("INFO", json_output=False)
        assert len(logging.getLogger("aisa").handlers) == 1
        get_logger("unit").info("password = hunter2hunter2")
        err = capsys.readouterr().err
        assert "hunter2" not in err and "[REDACTED]" in err
        configure_logging("CRITICAL")
        assert get_logger("x").name == "aisa.x" and get_logger("aisa.y").name == "aisa.y"
