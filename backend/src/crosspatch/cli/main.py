"""Tiny authenticated CLI for the CrossPatch incident room."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

from crosspatch.cli.client import CrossPatchClient
from crosspatch.cli.render import render_event, render_json, render_warrant

app = typer.Typer(help="CrossPatch incident controls")
incident_app = typer.Typer(help="Open incidents")
room_app = typer.Typer(help="Stream an incident room")
warrant_app = typer.Typer(help="Approve or reject pending warrants")
case_app = typer.Typer(help="Export a signed case file")
judge_token_app = typer.Typer(help="List, rotate, and revoke judge access tokens")
app.add_typer(incident_app, name="incident")
app.add_typer(room_app, name="room")
app.add_typer(warrant_app, name="warrant")
app.add_typer(case_app, name="case")
app.add_typer(judge_token_app, name="judge-token")


def _client(context: typer.Context) -> CrossPatchClient:
    if context.obj is not None:
        return context.obj
    context.obj = CrossPatchClient(
        base_url=os.environ.get("CROSSPATCH_API_URL", "https://localhost"),
        token=os.environ.get("CROSSPATCH_TOKEN", ""),
        origin=os.environ.get("CROSSPATCH_ORIGIN", "https://localhost"),
        csrf_token=os.environ.get("CROSSPATCH_CSRF_TOKEN"),
        step_up_token=os.environ.get("CROSSPATCH_STEP_UP_TOKEN"),
    )
    return context.obj


@incident_app.command("open")
def open_incident(context: typer.Context, scenario: str) -> None:
    typer.echo(render_json(_client(context).open_incident(scenario)))


@room_app.command("stream")
def stream_room(
    context: typer.Context,
    incident_id: str,
    last_event_id: Annotated[str | None, typer.Option("--last-event-id")] = None,
) -> None:
    for event in _client(context).stream_room(incident_id, last_event_id):
        typer.echo(render_event(event))


@warrant_app.command("approve")
def approve_warrant(context: typer.Context, warrant_id: str) -> None:
    client = _client(context)
    warrant = client.get_warrant(warrant_id)
    typer.echo(render_warrant(warrant))
    if not typer.confirm("Approve this exact warrant?"):
        typer.echo("Approval cancelled")
        raise typer.Exit(code=1)
    digest = warrant.get("warrant_sha256")
    if not isinstance(digest, str):
        raise typer.BadParameter("warrant response omitted warrant_sha256")
    typer.echo(render_json(client.approve_warrant(warrant_id, digest)))


@warrant_app.command("reject")
def reject_warrant(context: typer.Context, warrant_id: str) -> None:
    client = _client(context)
    warrant = client.get_warrant(warrant_id)
    typer.echo(render_warrant(warrant))
    if not typer.confirm("Reject this exact warrant?"):
        typer.echo("Rejection cancelled")
        raise typer.Exit(code=1)
    digest = warrant.get("warrant_sha256")
    if not isinstance(digest, str):
        raise typer.BadParameter("warrant response omitted warrant_sha256")
    typer.echo(render_json(client.reject_warrant(warrant_id, digest)))


@case_app.command("export")
def export_case(
    context: typer.Context,
    incident_id: str,
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    archive = _client(context).export_case(incident_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(archive)
    typer.echo(str(output))


@judge_token_app.command("rotate")
def rotate_judge_token(
    context: typer.Context,
    incident_id: Annotated[str | None, typer.Argument()] = None,
) -> None:
    if not typer.confirm("Rotate the judge token?"):
        typer.echo("Rotation cancelled")
        raise typer.Exit(code=1)
    typer.echo(render_json(_client(context).rotate_judge_token(incident_id)))


@judge_token_app.command("list")
def list_judge_tokens(context: typer.Context) -> None:
    typer.echo(render_json(_client(context).list_judge_tokens()))


@judge_token_app.command("revoke")
def revoke_judge_token(context: typer.Context, token_id: str) -> None:
    if not typer.confirm(f"Revoke judge token {token_id}?"):
        typer.echo("Revocation cancelled")
        raise typer.Exit(code=1)
    typer.echo(render_json(_client(context).revoke_judge_token(token_id)))


if __name__ == "__main__":  # pragma: no cover
    app()
